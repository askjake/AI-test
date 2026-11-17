"""Local full-procedure intake. No model calls, target contact, or execution."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets as _secrets
import shutil
import tempfile
from typing import Literal, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from .target_setup import PasswordSaveRequest, TargetSetupService
from . import connection_intake as CI

RDP_LINE = re.compile(r'(?i)\brdp\b[^\n]*?\bto\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*)(?::(?P<port>\d{1,5}))?\s*[.,;]?\s*$')
USER_LINE = re.compile(r'(?i)^(?:(?:user(?:name)?|login)\s*[:=]\s*)?([\w.@\\-]+)$')
# Strip a 'password:' / 'password=' prefix only when it is a label at the start of the line.
PASSWORD_LABEL = re.compile(r'(?i)^\s*password\s*[:=]\s*')
HOSTNAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
ELEVATION = '([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
MUTATING = re.compile(r'(?i)Stop-Service|Start-Service|Restart-Service|Set-Service|\bSet-|\bRemove-|\bNew-|\bKill\b|Stop-Process|taskkill|\bformat\b|\bflash|\breboot\b|Restart-Computer')
READ_ONLY = re.compile(r'(?i)IsInRole|Get-Service|Get-NetTCPConnection|Invoke-WebRequest|Chrome|browser|http://|\bGet-')
FINGERPRINT = re.compile(r'(?i)^(sha256|sha1):([0-9a-f:]+)$')
CONTROL = re.compile(r'[\x00-\x1f\x7f]')
NESTED_FINDING = ('Nested Remote Desktop: hop 1 is opened from the runner desktop and each later hop is opened inside the '
                  'previous desktop with Windows Remote Desktop. The chain is executable only after the hop-1 certificate is reviewed.')
NESTED_SENTENCE = 'Hops 2..N are opened inside the previous desktop with Windows Remote Desktop.'
OPEN_ADMIN = ('Open Windows PowerShell as Administrator: right-click Windows PowerShell and choose "Run as administrator". '
              'If a User Account Control box asks only Yes/No, choose Yes; if it asks for a user name or password, stop and report it.')
FORBIDDEN_RECOVERY = re.compile(r'(?i)\b(?:start\.cmd|start\.ps1|Manage-Service\.ps1|Stop-Process|taskkill)\b|\s-Force\b')


class IntakeError(ValueError):
    """Operator-facing message; ``field`` names the form field it belongs to (default: the goal text)."""

    def __init__(self, message: str = '', field: str = 'procedure') -> None:
        super().__init__(message)
        self.field = field


class ConnectionEditError(ValueError):
    def __init__(self, errors: list[dict]):
        super().__init__('Connection edit failed validation.')
        self.errors = errors


class IntakeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    procedure: SecretStr


class Hop(BaseModel):
    order: int
    protocol: str = 'rdp'
    host: str
    port: int = 3389
    user: str
    password_reference: str
    opened_from: str
    label: Optional[str] = None
    certificate_name: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    identity_policy: Literal['stop', 'accept_reviewed_prompt'] = 'stop'
    # VNC only (ignored for RDP, so existing RDP drafts and hashes are unchanged)
    display: Optional[int] = None
    auth_method: Literal['vnc-password', 'username-password'] = 'vnc-password'


class Gateway(BaseModel):
    """SSH gateway of a VNC-through-SSH procedure (a jump host, never a desktop).  Names of saved files only: no secret value lives here."""
    host: str
    port: int = 22
    user: str
    password_reference: str
    known_hosts_reference: Optional[str] = None
    host_key_algorithm: Optional[str] = None
    host_key_fingerprint: Optional[str] = None
    host_key_source: Optional[Literal['discovered', 'pasted']] = None
    host_key_approved_at: Optional[str] = None


GATEWAY_SESSION_END_TEXT = ("Session end: only the application instance this test opened may be closed; no other window or application is closed; "
                            "this run's own VNC viewer and SSH tunnel are ended; the remote session is never logged off, locked or shut down.")

GATEWAY_FINDINGS = [
    GATEWAY_SESSION_END_TEXT,
    "VNC through SSH: the runner opens an SSH tunnel to the gateway and then its VNC viewer on that tunnel. The gateway is not a desktop and no second desktop is opened.",
    "SSH host key: the gateway's host key must be reviewed and approved by an operator before a project can be created. Connections then use StrictHostKeyChecking=yes with the approved known-hosts reference; a changed key refuses the connection.",
    "Credentials are saved once in owner-only secret storage; this draft, its manual and the project files hold reference names only.",
    "This release runs connection tests only: the operating steps are saved with the project but are not executed.",
]


def gateway_findings(findings) -> list[str]:
    """Findings of a VNC-through-SSH draft: the generic VNC 'leave applications open' session-end line is replaced by the gateway one."""
    return [f for f in findings if not str(f).startswith('Session end:') and f not in GATEWAY_FINDINGS] + list(GATEWAY_FINDINGS)


class Step(BaseModel):
    order: int
    title: str
    kind: str
    instructions: str
    completion_checks: list[str]
    mutating: bool = False
    read_only_ok: bool = False


def upgrade_draft(raw: dict) -> dict:
    """Return a v2-shaped copy of a v1 or v2 draft dict (pure; defaults only)."""
    data = dict(raw)
    data.pop('readiness', None)  # computed, never stored
    if int(data.get('schema_version') or 1) < 2:
        data['schema_version'] = 2
        # v1 steps carry no run-safety flags: classify them now instead of calling a Stop-Service
        # step "read-only" by default.
        upgraded = []
        for st in data.get('steps') or []:
            if isinstance(st, dict) and 'mutating' not in st:
                m, r = classify_step(str(st.get('instructions', '')), str(st.get('title', '')), str(st.get('kind', 'procedure-step')))
                st = {**st, 'mutating': m, 'read_only_ok': r}
            upgraded.append(st)
        data['steps'] = upgraded
    if data.get('final_hop') in (None, 0):
        data['final_hop'] = len(data.get('connections') or [])
    data.setdefault('project', None)
    data.setdefault('last_test', None)
    return data


class ProcedureDraft(BaseModel):
    id: str
    title: str
    status: str = 'draft-only'
    connections: list[Hop]
    steps: list[Step]
    action_context_hop: int
    execution_supported: bool = False
    findings: list[str]
    manual: str
    schema_version: int = 2
    final_hop: int = 0
    project: Optional[dict] = None
    last_test: Optional[dict] = None
    session_end: Optional[dict] = None     # VNC: what happens to remote apps / the viewer / the remote session when the run ends
    gateway: Optional[Gateway] = None      # VNC through SSH only
    target_confirmation: Optional[dict] = None   # {'config_hash','at'}: operator confirmed gateway, destination and account for exactly these settings

    @model_validator(mode='before')
    @classmethod
    def _upgrade(cls, value):
        return upgrade_draft(value) if isinstance(value, dict) else value


def connection_config_hash(draft) -> str:
    """Stable fingerprint of everything that decides WHICH machines a run touches and how it signs in.

    A connection test result and a created project are valid only for the hash they were made with;
    any edit to a host, port, user, saved credential reference, hop-1 certificate or identity policy
    changes the hash and therefore invalidates both.
    """
    rows = [[h.order, h.host, h.port, h.user, h.password_reference, h.certificate_name or '',
             h.certificate_fingerprint or '', h.identity_policy] + ([h.protocol, h.display, h.auth_method] if h.protocol != 'rdp' else [])
            for h in draft.connections]
    gw = getattr(draft, 'gateway', None)
    if gw is not None:   # only gateway drafts: every other draft keeps its previous hash
        rows.append(['gateway', gw.host, gw.port, gw.user, gw.password_reference, gw.known_hosts_reference or '', gw.host_key_fingerprint or ''])
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode('utf-8')).hexdigest()


def classify_step(chunk: str, title: str, kind: str = 'procedure-step') -> tuple[bool, bool]:
    """Pure: (mutating, read_only_ok). Operator checkpoints are never read_only_ok."""
    text = title + '\n' + chunk
    mutating = bool(MUTATING.search(text))
    read_only_ok = (not mutating) and kind != 'operator-checkpoint' and bool(READ_ONLY.search(text))
    return mutating, read_only_ok


def _reference_exists(secrets_root: str, reference: str) -> bool:
    if not reference or '/' in reference or reference.startswith('.'):
        return False
    p = Path(secrets_root) / reference
    return p.is_file() and not p.is_symlink()  # existence only; never read


def compute_readiness(draft: ProcedureDraft, secrets_root: str) -> list[dict]:
    items = []
    for h in draft.connections:
        ok = _reference_exists(secrets_root, h.password_reference)
        items.append({'key': f'credential-hop-{h.order}', 'label': f'Hop {h.order} credential saved',
                      'state': 'known' if ok else 'required',
                      'detail': f'Saved reference {h.password_reference}' if ok else f'Save a password for hop {h.order}.'})
    if draft.connections and draft.connections[0].protocol == 'vnc':
        h1 = draft.connections[0]
        supported = h1.auth_method == 'vnc-password'
        items.append({'key': 'auth-method', 'label': 'VNC authentication method', 'state': 'known' if supported else 'required',
                      'detail': ('Classic VNC password authentication' + ('; the username is kept for reference and is not sent.' if h1.user else '.'))
                      if supported else "The runner's VNC viewer supports password-only authentication; a username + password method cannot be executed."})
        items.append({'key': 'identity', 'label': 'Remote identity', 'state': 'optional',
                      'detail': 'VNC offers no machine/account identity to read: a run confirms only that the viewer opened and a desktop image was captured.'})
        gw = getattr(draft, 'gateway', None)
        if gw is not None:
            ok_pw = _reference_exists(secrets_root, gw.password_reference)
            items.append({'key': 'gateway-credential', 'label': 'SSH gateway credential saved', 'state': 'known' if ok_pw else 'required',
                          'detail': f'Saved reference {gw.password_reference}' if ok_pw else 'Save the SSH gateway password.'})
            ok_hk = bool(gw.known_hosts_reference and gw.host_key_fingerprint and _reference_exists(secrets_root, gw.known_hosts_reference))
            items.append({'key': 'gateway-host-key', 'label': 'SSH gateway host key reviewed and approved', 'state': 'known' if ok_hk else 'required',
                          'detail': f'{gw.host_key_algorithm} {gw.host_key_fingerprint}' if ok_hk else
                          'Discover or paste the gateway host key and approve it after comparing its fingerprint with one obtained independently.'})
            confirmed = (draft.target_confirmation or {}).get('config_hash') == connection_config_hash(draft)
            items.append({'key': 'target-confirmation', 'label': 'Gateway, destination and account confirmed', 'state': 'known' if confirmed else 'required',
                          'detail': 'Confirmed for exactly these settings.' if confirmed else
                          'Confirm the gateway, destination and account before creating the project; any later change asks again.'})
    if draft.connections and draft.connections[0].protocol != 'vnc':
        h1 = draft.connections[0]
        ok = bool(h1.certificate_name and h1.certificate_fingerprint)
        items.append({'key': 'certificate-hop-1', 'label': 'Hop 1 certificate reviewed', 'state': 'known' if ok else 'required',
                      'detail': f'{h1.certificate_name} {h1.certificate_fingerprint}' if ok else 'Probe and review the hop-1 certificate name and fingerprint.'})
    real = [s for s in draft.steps if s.kind != 'needs-input']
    items.append({'key': 'operating-steps', 'label': 'Operating steps present', 'state': 'known' if real else 'optional',
                  'detail': f'{len(real)} steps' if real else 'Connection-only procedure.'})
    cps = [s.order for s in draft.steps if s.kind == 'operator-checkpoint']
    items.append({'key': 'checkpoints', 'label': 'Operator checkpoints noted', 'state': 'known' if cps else 'optional',
                  'detail': 'Steps ' + ', '.join(map(str, cps)) if cps else 'No operator checkpoints.'})
    n = len(draft.connections)
    if draft.connections and draft.connections[0].protocol == 'vnc':
        items.append({'key': 'final-hop', 'label': 'Final desktop', 'state': 'known', 'detail': 'Operating steps run on the VNC desktop.'})
        items.append({'key': 'session-end', 'label': 'When the run ends', 'state': 'known', 'detail': GATEWAY_SESSION_END_TEXT if getattr(draft, 'gateway', None) is not None else CI.SESSION_END_TEXT})
        return items
    items.append({'key': 'final-hop', 'label': 'Final hop', 'state': 'known',
                  'detail': f'Operating steps run inside the hop {n} desktop' + (' (nested Remote Desktop).' if n > 1 else '.')})
    return items


def _with_readiness(draft: ProcedureDraft, secrets_root: str) -> ProcedureDraft:
    ready = not any(i['state'] == 'required' for i in compute_readiness(draft, secrets_root))
    return draft.model_copy(update={'execution_supported': ready, 'final_hop': len(draft.connections)})


def public_view(draft: ProcedureDraft, secrets_root: str) -> dict:
    """Route-facing JSON: references and states only, never a password."""
    data = draft.model_dump(mode='json')
    if getattr(draft, 'gateway', None) is None:      # plain RDP/VNC drafts keep their exact previous public shape
        data.pop('gateway', None); data.pop('target_confirmation', None)
    readiness = compute_readiness(draft, secrets_root)
    for c in data['connections']:
        c['credential'] = {'state': 'saved' if _reference_exists(secrets_root, c['password_reference']) else 'missing',
                           'reference': c['password_reference']}
        # Contract shape: certificate is a nested object; hop 1 only is pinned, later hops are not applicable.
        if c.get('protocol') == 'vnc':
            c['certificate'] = {'state': 'not_applicable', 'name': '', 'fingerprint': ''}
            c['vnc'] = {'display': c.get('display'), 'tcp_port': c['port'], 'auth_method': c.get('auth_method'),
                        'username_sent': False, 'address_form': (f":{c['display']}" if c.get('display') is not None else f"::{c['port']}")}
            c['opened_from'] = 'runner (VNC viewer) through the SSH gateway' if getattr(draft, 'gateway', None) is not None else 'runner (VNC viewer)'
        elif c['order'] == 1:
            name, fp = c.get('certificate_name'), c.get('certificate_fingerprint')
            c['certificate'] = {'state': 'reviewed' if (name and fp) else 'required',
                                'name': name or '', 'fingerprint': fp or ''}
        else:
            c['certificate'] = {'state': 'not_applicable', 'name': '', 'fingerprint': ''}
        c['predecessor'] = c['order'] - 1 if c['order'] > 1 else None
    data['readiness'] = {'items': readiness}
    project = data.get('project')
    if isinstance(project, dict):
        pname = project.get('name') or project.get('project_name')
        data['project'] = ({**project, 'name': pname, 'project_name': pname} if pname else None)
    data['execution_supported'] = not any(i['state'] == 'required' for i in readiness)
    data['final_hop'] = len(draft.connections)
    cfg = connection_config_hash(draft)
    # Currency flags: the UI blocks a stale project / test; the server enforces the same rule at run start.
    if isinstance(data.get('last_test'), dict):
        data['last_test'] = {**data['last_test'], 'current': data['last_test'].get('config_hash') == cfg}
        data['last_test'].pop('config_hash', None)
    if isinstance(data.get('project'), dict):
        data['project']['current'] = data['project'].get('config_hash') == cfg
        data['project'].pop('config_hash', None)
    gw = getattr(draft, 'gateway', None)
    if gw is not None:
        hk_ok = bool(gw.known_hosts_reference and gw.host_key_fingerprint and _reference_exists(secrets_root, gw.known_hosts_reference))
        data['gateway'] = {'host': gw.host, 'port': gw.port, 'user': gw.user, 'route': 'ssh-jump',
                           'credential': {'state': 'saved' if _reference_exists(secrets_root, gw.password_reference) else 'missing', 'reference': gw.password_reference},
                           'host_key': {'state': 'approved' if hk_ok else 'required', 'algorithm': gw.host_key_algorithm or '', 'fingerprint': gw.host_key_fingerprint or '',
                                        'reference': gw.known_hosts_reference or '', 'source': gw.host_key_source or '', 'approved_at': gw.host_key_approved_at or ''}}
        conf = draft.target_confirmation or {}
        data['target_confirmation'] = {'confirmed': bool(conf), 'current': conf.get('config_hash') == cfg, 'at': conf.get('at', ''), 'config_hash': cfg}
    return data


def assert_no_secret(obj, secrets: list[str]) -> None:
    text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    for s in secrets:
        assert s and s not in text, 'a staged secret value appeared in output'


def _parse(text: str):
    if not 12 <= len(text) <= 40000 or '\0' in text:
        raise IntakeError('Paste a procedure between 12 and 40000 characters, without NUL characters.')
    lines = text.replace('\r\n','\n').splitlines()
    vnc_lines, rdp_lines = CI.find_connection_lines(lines)
    if vnc_lines:
        return _parse_vnc(lines, vnc_lines, rdp_lines)
    used=set(); parsed=[]
    for i,line in enumerate(lines):
        match=RDP_LINE.search(line.strip())
        if not match: continue
        host=match['host'].rstrip('.')
        try: ipaddress.ip_address(host)
        except ValueError:
            if not HOSTNAME.fullmatch(host):
                raise IntakeError('An RDP host is not a valid address or hostname.')
        port=int(match['port'] or 3389)
        if not 1<=port<=65535:raise IntakeError('An RDP port is outside 1 through 65535.')
        following=[j for j in range(i+1,len(lines)) if lines[j].strip()][:2]
        if len(following)!=2:raise IntakeError('Each RDP connection needs the username and password on the next two nonempty lines.')
        u,p=following
        username=USER_LINE.fullmatch(lines[u].strip())
        if not username:raise IntakeError('An RDP username could not be identified. Put it on a separate line after the RDP host.')
        password=PASSWORD_LABEL.sub('',lines[p],count=1)
        if not password.strip() or len(password)>1024 or RDP_LINE.search(password) or re.match(r'^\d+[.)]\s',password):
            raise IntakeError('An RDP password could not be identified. Put it on a separate line after its username.')
        parsed.append((host,port,username[1],SecretStr(password)))
        used.update((i,u,p))
    if not parsed:raise IntakeError('No RDP connection was identified. Use \u201cRDP to HOST\u201d, followed by username and password on separate lines.')
    if len(parsed)>8:raise IntakeError('This intake supports up to eight ordered RDP hops.')
    body='\n'.join(line for i,line in enumerate(lines) if i not in used).strip()
    # Known connection values never become manual or model prose.
    for host,port,user,password in parsed:
        for value in sorted((host,user,password.get_secret_value()),key=len,reverse=True):
            body=body.replace(value,'[saved connection value]')
    if re.search(r'(?im)^\s*(?:password|passwd|secret|token)\s*[:=]',body):
        raise IntakeError('A credential field remains outside a connection block. Move it directly below the matching RDP username.')
    return _finish_parse(body, parsed)


class _Conn(tuple):
    """A (host, port, user, SecretStr) tuple that also carries protocol-specific extras (unpacks exactly like the RDP tuples)."""

    def __new__(cls, host, port, user, password, **extra):
        obj = super().__new__(cls, (host, port, user, password))
        obj.extra = extra
        return obj


def _parse_vnc(lines: list[str], vnc_lines: list[int], rdp_lines: list[int]):
    if rdp_lines:
        raise IntakeError('This goal mixes RDP and VNC connections. Mixed RDP/VNC chains are not supported: use one VNC connection, or an RDP chain.')
    if len(vnc_lines) > 1:
        raise IntakeError('Only one VNC connection per procedure is supported; found %d \u201cVNC to \u2026\u201d lines.' % len(vnc_lines))
    try:
        block = CI.parse_vnc_block(lines, vnc_lines[0])
    except CI.ConnectionBlockError as exc:
        raise IntakeError(exc.message, field=exc.field) from None
    used = set(block.consumed)
    stray = CI.unconsumed_credential_lines(lines, used)
    if stray:
        raise IntakeError('Line %d looks like a credential but is not part of the VNC connection block. Put the username/password lines directly '
                          'below \u201cVNC to HOST\u201d. Nothing was sent to the model.' % (stray[0] + 1), field='vnc.password')
    body = '\n'.join(line for i, line in enumerate(lines) if i not in used).strip()
    for value in sorted((block.host, block.user or '', block.password), key=len, reverse=True):
        if value:
            body = body.replace(value, '[saved connection value]')
    conn = _Conn(block.host, block.port, block.user or '', SecretStr(block.password), protocol='vnc', display=block.display)
    return _finish_parse(body, [conn], protocol='vnc')


def _finish_parse(body: str, parsed: list, protocol: str = 'rdp'):
    needs_input = not body.strip()
    if not re.search(r'(?m)^\s*\d+[.)]\s+.+$',body):
        body = '1. ' + (body if body else 'Describe what should happen after connecting.')
    sections=list(re.finditer(r'(?m)^\s*(\d+)[.)]\s+(.+)$',body))
    preamble=body[:sections[0].start()].strip()
    steps=[];findings=[]
    for n,match in enumerate(sections):
        chunk=body[match.start():sections[n+1].start() if n+1<len(sections) else len(body)].strip()
        chunk=re.sub(r'(?m)^\s*powershell\s*$','',chunk)
        if n==0 and preamble:chunk='Before this step: '+preamble+'\n\n'+chunk
        if 'WindowsIdentity' in chunk and '.Groups' in chunk and 'S-1-5-32-544' in chunk:
            chunk=re.sub(r'(?m)^.*WindowsIdentity.*\.Groups.*S-1-5-32-544.*$',ELEVATION,chunk)
            findings.append('Elevation check corrected: administrator-group membership alone does not prove an elevated token. Require IsInRole(Administrator) = True.')
        if 'IsInRole' in chunk and not re.search(r'(?i)run as administrator', chunk):
            first_line, _, rest_lines = chunk.partition('\n')
            chunk = first_line + '\n' + OPEN_ADMIN + ('\n' + rest_lines if rest_lines else '')
            findings.append('An explicit "open PowerShell as Administrator" action was added before the elevation check; the check alone does not open an elevated window.')
        title_text=match[2].strip()
        if 'Get-NetTCPConnection' in chunk and re.search(r'(?i)serial.*handle|handle.*release',title_text):
            title_text='Confirm the TCP port is free; check serial ownership separately'
            chunk=re.sub(r'^.*?(?=\n|$)',title_text,chunk,count=1)
        manual=bool(re.search(r'(?i)\b(?:flash|swap wires|physical(?:ly)?|hardware work|COM\d+.*(?:Guide|Select))\b',chunk))
        checks=[line.strip(' -') for line in chunk.splitlines() if re.match(r'(?i)^\s*(?:must|should)\b',line)]
        if 'IsInRole' in chunk:checks.append('The current token is elevated: IsInRole(Administrator) returns True. Otherwise stop and reopen PowerShell as administrator.')
        if 'IsInRole' in chunk:checks.append('PowerShell was opened as Administrator. A consent-only User Account Control box may be approved; stop if a user name or password is requested.')
        if re.search(r'(?i)\b(?:Stop|Start)-Service\b',chunk):checks.append('If the service does not reach the expected state in time, stop and report the failure. Never force it: no -Force, Stop-Process or taskkill, and never start.cmd, start.ps1 or Manage-Service.ps1.')
        if re.search(r'(?i)\bStop-Service\b',chunk):checks.append('The named Windows service reaches Stopped before any hardware work.')
        if re.search(r'(?i)\bStart-Service\b',chunk):checks.append('The named Windows service reaches Running; service status alone is not application health.')
        if 'Get-NetTCPConnection' in chunk:checks.append('The specified TCP port has no remaining connections. Wait if entries remain; this does not establish COM-handle release.')
        if 'Invoke-WebRequest' in chunk:checks.append('The local application health request returns HTTP 200.')
        if manual:checks.append('Operator completion is required; do not infer a physical action or result from screenshots or HTTP status.')
        kind='operator-checkpoint' if manual else 'procedure-step'
        mutating,read_only_ok=classify_step(chunk,title_text,kind)
        steps.append(Step(order=n+1,title=title_text,kind=kind,instructions=chunk,completion_checks=list(dict.fromkeys(checks)),
                          mutating=mutating,read_only_ok=read_only_ok))
    service_names=set(re.findall(r'(?i)\b(?:Stop|Start|Get)-Service\s+-Name\s+[\'"]?([A-Za-z0-9_.-]+)',body))
    if len(service_names)==1:title=next(iter(service_names))+' service maintenance'
    elif protocol=='vnc':title='VNC desktop operating procedure'
    else:title='Remote desktop operating procedure'
    if protocol=='vnc':
        findings.insert(0,'Draft only: reachability and live execution have not been verified. VNC offers no machine or account identity to read, so a run confirms only that the viewer opened and a desktop image was captured.')
        findings.append(CI.SESSION_END_TEXT)
        if getattr(parsed[0],'extra',{}) and parsed[0][2]:
            findings.append('The username is stored for reference. Classic VNC password authentication has no username, so it is not sent.')
        _pw = parsed[0][3].get_secret_value() if isinstance(parsed[0], tuple) else ''      # (update_procedure passes saved Hop objects: no password text here)
        if _pw != _pw.strip():
            findings.append('The VNC password has leading or trailing spaces and they are kept exactly as typed. If the connection test fails to log in, check for a pasted trailing space.')
        if not _pw.isascii():
            findings.append('The VNC password contains non-ASCII characters. Classic VNC uses raw bytes and servers differ on UTF-8 versus Latin-1; if login fails, try an ASCII password.')
        if re.search(r'(?i)\b(?:log\s*off|sign\s*out|shut\s*down|lock the (?:screen|desktop|session))\b',body):
            findings.append('The text mentions logging off, locking or shutting down. The application never does this on its own; write it as an explicit step if you want it and treat it as a change.')
    elif len(parsed)>1:findings.insert(0,NESTED_FINDING+' All hops are preserved; this is not a direct connection to the final host.')
    else:findings.insert(0,'Draft only: target identity, reachability, and live execution have not been verified.')
    forbidden=sorted({m.group(0).strip() for m in FORBIDDEN_RECOVERY.finditer(body)},key=str.lower)
    if forbidden:findings.append('The pasted text mentions '+', '.join(forbidden)+'. The application never types these as a substitute or recovery; if a service does not stop or start in time, the run reports the failure instead.')
    if re.search(r'(?i)COM\d+',body):findings.append('A free TCP port does not prove a serial handle is released. Confirm COM-port ownership separately before hardware work; never force-release a handle.')
    if any(s.kind=='operator-checkpoint' for s in steps):findings.append('Physical work and receiver button checks require operator completion. No hardware action or physical result is inferred from HTTP 200.')
    if re.search(r'(?i)flash|swap wires|hardware work',body):findings.append('Hardware work is not specified sufficiently for automation. Keep it as an operator checkpoint; do not infer firmware, wiring, or a flashing command.')
    if needs_input:
        steps=[Step(order=1,title='Add the operating procedure',kind='needs-input',instructions='',completion_checks=[])]
        findings.insert(0,'Connections saved. Add what should happen after connecting; numbered steps are optional.')
    findings.append('No service, browser, shell, model, or network action was executed during intake.')
    return parsed,steps,title,findings


def render_manual(title, hops, steps, findings, gateway=None):
    if hops and getattr(hops[0], 'protocol', 'rdp') == 'vnc':
        h = hops[0]
        where = f':{h.display}' if h.display is not None else f'::{h.port}'
        manual = '# ' + title + '\n\n## Connection\n\n'
        if gateway is not None:
            manual += (f'1. SSH tunnel to the gateway {gateway.user}@{gateway.host}:{gateway.port}; use saved reference `{gateway.password_reference}`. '
                       + (f'Host key {gateway.host_key_algorithm} {gateway.host_key_fingerprint} approved' + (f' on {gateway.host_key_approved_at}' if gateway.host_key_approved_at else '')
                          if gateway.host_key_fingerprint else 'Host key NOT YET APPROVED (a project cannot be created until an operator approves it)')
                       + '; connections require this exact key.\n')
            manual += f'2. VNC to {h.host}{where} (TCP {h.port}) through that tunnel; use saved reference `{h.password_reference}`. Opened by the runner\u2019s VNC viewer.'
            manual += '\n\nAll operating actions below apply on the VNC desktop. ' + GATEWAY_SESSION_END_TEXT + '\n'
            manual += '\n\n## Procedure\n\n'+'\n\n'.join('### '+s.title+'\n\nType: '+s.kind+('; mutating' if getattr(s,'mutating',False) else '')+'\n\n'+s.instructions+'\n\nCompletion checks:\n'+'\n'.join('- '+check for check in s.completion_checks) for s in steps)
            manual += '\n\n## Readiness and evidence\n\n'+'\n'.join('- '+f for f in findings)
            return manual
        manual += f'1. VNC to {h.host}{where} (TCP {h.port}); use saved reference `{h.password_reference}`.' + (' A username was recorded in the draft but is not sent (classic VNC password authentication) and is not repeated here.' if h.user else '') + ' Opened by the runner\u2019s VNC viewer.'
        manual += '\n\nAll operating actions below apply on the VNC desktop. ' + CI.SESSION_END_TEXT + '\n'
        manual += '\n\n## Procedure\n\n'+'\n\n'.join('### '+s.title+'\n\nType: '+s.kind+('; mutating' if getattr(s,'mutating',False) else '')+'\n\n'+s.instructions+'\n\nCompletion checks:\n'+'\n'.join('- '+check for check in s.completion_checks) for s in steps)
        manual += '\n\n## Readiness and evidence\n\n'+'\n'.join('- '+f for f in findings)
        return manual
    manual='# '+title+'\n\n## Connection sequence\n\n'
    manual+='\n'.join(f'{h.order}. RDP to {h.host}:{h.port} as {h.user}'+(f' ({h.label})' if getattr(h,'label',None) else '')
                      +f'; use saved reference `{h.password_reference}`. Opened from {h.opened_from}.' for h in hops)
    if len(hops)>1:
        manual+='\n\n'+NESTED_SENTENCE+' Hop 1 is opened from the runner desktop; only saved reference names are recorded here.'
    manual+=f'\n\nAll operating commands, browser localhost URLs, and COM-port checks below apply inside the final RDP desktop (hop {len(hops)}), not on the dashboard server or the first desktop.\n'
    manual+='\n\n## Procedure\n\n'+'\n\n'.join('### '+s.title+'\n\nType: '+s.kind+('; mutating' if getattr(s,'mutating',False) else '')+'\n\n'+s.instructions+'\n\nCompletion checks:\n'+'\n'.join('- '+check for check in s.completion_checks) for s in steps)
    manual+='\n\n## Readiness and evidence\n\n'+'\n'.join('- '+f for f in findings)
    return manual


def _opened_from(i: int) -> str:
    return 'runner desktop' if i == 0 else f'RDP desktop from hop {i} (Windows Remote Desktop inside the previous desktop)'


def build_procedure(text: str, target_service: TargetSetupService, state_root: str) -> ProcedureDraft:
    parsed,steps,title,findings=_parse(text)
    key=uuid.uuid4().hex
    root=Path(state_root).resolve()/'procedure-drafts'
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    root.chmod(0o700)
    temp=Path(tempfile.mkdtemp(prefix='.intake-',dir=root)); saved=[]
    try:
        hops=[]
        for i,item in enumerate(parsed):
            host,port,user,password=item
            extra=getattr(item,'extra',{}) or {}
            protocol=extra.get('protocol','rdp')
            reference=f'procedure-{key}-hop-{i+1}.{protocol}.pw'
            response=target_service.save_password(PasswordSaveRequest(kind=protocol,reference_name=reference,password=password))
            saved.append(response.reference_name)
            if protocol=='vnc':
                hops.append(Hop(order=i+1,protocol='vnc',host=host,port=port,user=user,password_reference=response.reference_name,
                                opened_from='runner (VNC viewer)',display=extra.get('display')))
            else:
                hops.append(Hop(order=i+1,host=host,port=port,user=user,password_reference=response.reference_name,opened_from=_opened_from(i)))
        manual=render_manual(title,hops,steps,findings)
        draft=ProcedureDraft(id=key,title=title,connections=hops,steps=steps,action_context_hop=len(hops),findings=findings,manual=manual,final_hop=len(hops),
                             session_end=(dict(CI.SESSION_END_DEFAULT) if hops and hops[0].protocol=='vnc' else None))
        draft=_with_readiness(draft,target_service._secrets_root())
        for filename,data in [('draft.json',draft.model_dump_json(indent=2)),('manual.md',manual)]:
            p=temp/filename;p.write_text(data);p.chmod(0o600)
        temp.rename(root/key)
        return draft
    except Exception:
        for reference in saved:
            (Path(target_service._secrets_root())/reference).unlink(missing_ok=True)
        shutil.rmtree(temp,ignore_errors=True)
        raise


def load_procedure(key: str,state_root: str) -> ProcedureDraft:
    if not re.fullmatch(r'[0-9a-f]{32}',key):raise IntakeError('Invalid procedure draft ID.')
    p=Path(state_root).resolve()/'procedure-drafts'/key/'draft.json'
    if not p.is_file() or p.is_symlink():raise IntakeError('Procedure draft was not found.')
    return ProcedureDraft.model_validate(json.loads(p.read_text()))


class ProcedureUpdateRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    instructions: SecretStr


def _persist(key: str, state_root: str, draft: ProcedureDraft) -> None:
    root=Path(state_root).resolve()/'procedure-drafts'/key
    for filename,data in [('draft.json',draft.model_dump_json(indent=2)),('manual.md',draft.manual)]:
        fd,name=tempfile.mkstemp(prefix='.update-',dir=root)
        try:
            with os.fdopen(fd,'w') as handle:handle.write(data)
            os.chmod(name,0o600);os.replace(name,root/filename)
        finally:
            if os.path.exists(name):os.unlink(name)

persist_draft = _persist  # public alias for the v2 routes


def update_procedure(key: str, instructions: str, state_root: str) -> ProcedureDraft:
    draft=load_procedure(key,state_root)
    if not instructions.strip():raise IntakeError('Describe what should happen after connecting before saving the procedure.')
    if len(instructions)>30000:raise IntakeError('The procedure is too long; use at most 30000 characters.')
    if any(RDP_LINE.search(line) or CI.VNC_LINE.search(line.strip()) for line in instructions.splitlines()) or CI.credential_guard_message(instructions) or re.search(r'(?im)^\s*(?:password|passwd|secret|token)\s*[:=]',instructions):
        raise IntakeError('Keep connection and password blocks in the initial goal. This field is for operating steps only.')
    if draft.connections and draft.connections[0].protocol=='vnc':
        _,steps,title,findings=_finish_parse(instructions.strip(),list(draft.connections),protocol='vnc')
        if draft.gateway is not None:
            title=draft.title
            findings=gateway_findings(findings)
    else:
        # Reuse the same step parser without reading or rewriting any stored password.
        blocks='\n'.join(f'RDP to {h.host}:{h.port}\n{h.user}\n[saved-password-reference]' for h in draft.connections)
        _,steps,title,findings=_parse(blocks+'\n'+instructions)
    updated=draft.model_copy(update={'steps':steps,'title':title,'findings':findings,
        'manual':render_manual(title,draft.connections,steps,findings,draft.gateway)})
    _persist(key,state_root,updated)
    return updated


_EDIT_KEYS = {'order','host','port','user','label','identity_policy','certificate_name','certificate_fingerprint','new_password','display','auth_method'}


def normalise_fingerprint(value: str) -> str | None:
    m = FINGERPRINT.match(value.strip())
    if not m:
        return None
    algo, digest = m[1].lower(), m[2].replace(':', '').lower()
    if not re.fullmatch(r'[0-9a-f]+', digest) or len(digest) != (64 if algo == 'sha256' else 40):
        return None
    return f'{algo}:{digest}'


def _validate_edits(draft: ProcedureDraft, edits: list[dict]) -> tuple[list[dict], dict[int, dict]]:
    errors: list[dict] = []; changes: dict[int, dict] = {}
    orders = {h.order for h in draft.connections}
    if not isinstance(edits, list) or not edits:
        return [{'field': 'connections', 'message': 'Provide at least one connection edit.'}], {}
    for idx, edit in enumerate(edits):
        if not isinstance(edit, dict):
            errors.append({'field': f'connections[{idx}]', 'message': 'Each edit must be an object.'}); continue
        order = edit.get('order')
        if not isinstance(order, int) or isinstance(order, bool) or order not in orders:
            errors.append({'field': f'connections[{idx}].order', 'message': 'This hop does not exist.'}); continue
        f = lambda name, o=order: f'connections[{o - 1}].{name}'  # zero-based position == order-1 (the UI maps it back)
        for extra in sorted(set(edit) - _EDIT_KEYS):
            errors.append({'field': f(extra), 'message': 'Unknown field.'})
        change = changes.setdefault(order, {})
        vnc = next(h for h in draft.connections if h.order == order).protocol == 'vnc'
        if vnc and 'display' in edit and 'port' in edit:
            errors.append({'field': f('port'), 'message': 'Give either the display number or the TCP port, not both.'})
        if 'host' in edit:
            host = edit['host']
            ok = isinstance(host, str)
            if ok:
                try: ipaddress.ip_address(host)
                except ValueError: ok = bool(HOSTNAME.fullmatch(host))
            if ok: change['host'] = host
            else: errors.append({'field': f('host'), 'message': 'Enter an IP address or hostname.'})
        if 'port' in edit:
            port = edit['port']
            if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                change['port'] = port
                if vnc and 'display' not in edit: change['display'] = port - 5900 if 5900 <= port <= 5999 else None
            else: errors.append({'field': f('port'), 'message': 'Port must be 1 through 65535.'})
        if 'display' in edit:
            display = edit['display']
            if not vnc: errors.append({'field': f('display'), 'message': 'A display number applies to VNC connections only.'})
            elif isinstance(display, int) and not isinstance(display, bool) and 0 <= display <= 99: change['display'] = display; change['port'] = 5900 + display
            else: errors.append({'field': f('display'), 'message': 'VNC display must be 0 through 99 (TCP 5900 plus the display). For another TCP port set the port instead.'})
        if 'auth_method' in edit:
            if not vnc: errors.append({'field': f('auth_method'), 'message': 'Authentication method applies to VNC connections only.'})
            elif edit['auth_method'] in ('vnc-password', 'username-password'): change['auth_method'] = edit['auth_method']
            else: errors.append({'field': f('auth_method'), 'message': "Use 'vnc-password' or 'username-password'."})
        if 'user' in edit:
            user = edit['user']
            if isinstance(user, str) and (user.strip() or vnc) and len(user) <= 256 and not CONTROL.search(user): change['user'] = user.strip() if vnc else user
            else: errors.append({'field': f('user'), 'message': 'Username must be 1-256 characters without control characters.' + (' (Leave it empty for password-only VNC.)' if vnc else '')})
        if 'label' in edit:
            label = edit['label']
            if label is None or (isinstance(label, str) and len(label) <= 120 and not CONTROL.search(label)): change['label'] = label or None
            else: errors.append({'field': f('label'), 'message': 'Label must be at most 120 characters.'})
        if vnc and ('identity_policy' in edit or 'certificate_name' in edit or 'certificate_fingerprint' in edit):
            errors.append({'field': f('identity_policy' if 'identity_policy' in edit else 'certificate_name'), 'message': 'Identity policy and certificates do not apply to VNC.'})
            continue
        if 'identity_policy' in edit:
            if edit['identity_policy'] in ('stop', 'accept_reviewed_prompt'): change['identity_policy'] = edit['identity_policy']
            else: errors.append({'field': f('identity_policy'), 'message': "Use 'stop' or 'accept_reviewed_prompt'."})
        for cert in ('certificate_name', 'certificate_fingerprint'):
            if cert not in edit: continue
            if order != 1:
                errors.append({'field': f(cert), 'message': 'Certificate review applies to hop 1 only.'}); continue
            value = edit[cert]
            if value is None: change[cert] = None; continue
            if cert == 'certificate_name':
                if isinstance(value, str) and value.strip() and len(value) <= 256 and not CONTROL.search(value): change[cert] = value.strip()
                else: errors.append({'field': f(cert), 'message': 'Certificate name must be 1-256 characters.'})
            else:
                norm = normalise_fingerprint(value) if isinstance(value, str) else None
                if norm: change[cert] = norm
                else: errors.append({'field': f(cert), 'message': 'Use sha256:<64 hex> or sha1:<40 hex>.'})
        if 'new_password' in edit and edit['new_password'] is not None:
            pw = edit['new_password']
            raw = pw.get_secret_value() if isinstance(pw, SecretStr) else pw
            if vnc and isinstance(raw, str) and len(raw.encode('utf-8')) > CI.MAX_VNC_PASSWORD_BYTES:
                errors.append({'field': f('new_password'), 'message': f'Classic VNC authentication uses at most {CI.MAX_VNC_PASSWORD_BYTES} bytes; a longer password would be silently truncated by the server.'})
            elif isinstance(raw, str) and raw.strip() and len(raw) <= 1024 and '\0' not in raw: change['new_password'] = SecretStr(raw)
            else: errors.append({'field': f('new_password'), 'message': 'Password must be 1-1024 characters.'})
    return errors, changes


def update_connections(key: str, edits: list[dict], state_root: str, target_service) -> ProcedureDraft:
    draft = load_procedure(key, state_root)
    errors, changes = _validate_edits(draft, edits)
    if errors:
        raise ConnectionEditError(errors)
    secrets_root = target_service._secrets_root()
    written: list[str] = []
    try:
        hops = []
        for h in draft.connections:
            change = dict(changes.get(h.order, {}))
            pw = change.pop('new_password', None)
            if pw is not None:
                reference = f'procedure-{key}-hop-{h.order}-{_secrets.token_hex(4)}.{h.protocol}.pw'
                resp = target_service.save_password(PasswordSaveRequest(kind=h.protocol, reference_name=reference, password=pw, overwrite=False))
                written.append(resp.reference_name)
                change['password_reference'] = resp.reference_name  # old reference file is left untouched
            hops.append(h.model_copy(update=change))
        hops = [Hop.model_validate(h.model_dump()) for h in hops]
        updated = draft.model_copy(update={'connections': hops, 'final_hop': len(hops),
                                           'manual': render_manual(draft.title, hops, draft.steps, draft.findings, draft.gateway)})
        if connection_config_hash(draft.model_copy(update={'connections': hops})) != connection_config_hash(draft):
            updated = updated.model_copy(update={'last_test': None})   # an old connection test no longer proves anything
        updated = _with_readiness(updated, secrets_root)
        _persist(key, state_root, updated)
        return updated
    except Exception:
        for reference in written:
            (Path(secrets_root) / reference).unlink(missing_ok=True)
        raise
