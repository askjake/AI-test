"""Local recognition of credential-bearing connection text (VNC intake + the guard that keeps credentials away from the model).

Pure standard library; imports nothing from the dashboard package so it is usable (and tested) anywhere.

VNC block syntax (documented in the UI and in docs/VNC_INTAKE.md)::

    VNC to HOST            display 0  = TCP 5900
    VNC to HOST:N          N = 0..99  = display N = TCP 5900+N          (the usual VNC meaning of a single colon)
    VNC to HOST::PORT      PORT = 1..65535 is the TCP port, taken literally (display shown only if 5900..5999)
    username: NAME         optional; labelled
    password: SECRET       required; labelled; classic VNC uses at most 8 bytes

``HOST:5901`` (a single colon followed by 100 or more) is AMBIGUOUS between "display" and "port" in different viewers and is rejected with a
message telling the operator to write ``:1`` or ``::5901``.  IPv6 literals are not accepted.  The username is stored but, with the classic
VNC password authentication the runner's viewer uses, it is NOT sent (that method has no username); choosing a username+password method is
reported as unsupported rather than silently ignored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

VNC_LINE = re.compile(r"(?i)^\s*(?:(?:connect|open|use)\s+(?:via\s+|using\s+|with\s+)?)?vnc\s+(?:connection\s+)?to\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<addr>::\d{1,5}|:\d{1,5})?\s*[.,;]?\s*$")
RDP_LINE = re.compile(r"(?i)\brdp\b[^\n]*?\bto\s+(?P<host>[A-Za-z0-9][A-Za-z0-9._-]*)(?::(?P<port>\d{1,5}))?\s*[.,;]?\s*$")
USER_LABEL = re.compile(r"(?i)^\s*(?:user(?:name)?|login)\s*[:=]\s?(?P<value>.*)$")
PASSWORD_LABEL = re.compile(r"(?i)^\s*(?:pass(?:word|wd)?|pwd)\s*[:=]\s?(?P<value>.*)$")
CREDENTIAL_LINE = re.compile(r"(?i)^\s*[\"']?(?:pass(?:word|wd|code|phrase)?|pwd|pw|pin|secret|token|api[_ -]?key|bearer)[\"']?\s*[:=]\s*\S")
URL_CREDENTIALS = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@")
INLINE_CREDENTIAL = re.compile(r"(?i)\b(?:passwords?|passwd|pwd|passphrase|api[_ -]?key|secret|token)\b\s*[:=]\s*(?!<saved[ _-]credential>|<credential[ _-]reference>|\$\{)\S")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
MAX_VNC_PASSWORD_BYTES = 8

SESSION_END_DEFAULT = {
    "remote_applications": "leave_open",     # the run never closes anything it did not open (a browser the procedure opened stays open)
    "automation_client": "disconnect",       # the run's own VNC viewer window is closed when the run ends
    "remote_session": "never_log_off",       # logging off / locking / shutting down the remote machine is never done automatically
}
SESSION_END_TEXT = (
    "Session end: remote applications (for example a browser the steps opened) are left open; only this run's own VNC viewer is disconnected when the "
    "run ends; the remote session is never logged off, locked or shut down by the application.")


class ConnectionBlockError(ValueError):
    """Operator-facing, secret-free message plus the form field it belongs to."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


@dataclass(frozen=True)
class VncBlock:
    host: str
    port: int
    display: int | None
    user: str | None
    password: str = ""          # never logged; callers wrap it in SecretStr immediately
    consumed: tuple = ()


def parse_vnc_address(addr: str | None) -> tuple[int, int | None]:
    """(tcp_port, display or None).  Raises ConnectionBlockError for ambiguous or out-of-range forms."""
    if not addr:
        return 5900, 0
    if addr.startswith("::"):
        port = int(addr[2:])
        if not 1 <= port <= 65535:
            raise ConnectionBlockError("vnc.port", "The VNC TCP port after '::' must be 1 through 65535.")
        return port, (port - 5900 if 5900 <= port <= 5999 else None)
    number = int(addr[1:])
    if number > 99:
        raise ConnectionBlockError(
            "vnc.port",
            f"'{addr}' is ambiguous: different VNC viewers read a single colon as a display number or as a TCP port. "
            f"Write ':{number % 100}' for display {number % 100} (TCP {5900 + number % 100}) or '::{number}' for TCP port {number}.")
    return 5900 + number, number


def parse_vnc_block(lines: list[str], index: int) -> VncBlock:
    match = VNC_LINE.search(lines[index].strip())
    if not match:
        raise ConnectionBlockError("vnc.host", "Write the connection as 'VNC to HOST' (optionally HOST:DISPLAY or HOST::PORT).")
    host = match["host"].rstrip(".")
    if not HOSTNAME.fullmatch(host):
        raise ConnectionBlockError("vnc.host", "The VNC host is not a valid IPv4 address or hostname (IPv6 literals are not supported).")
    if match["addr"] and match["addr"].startswith("::") and re.fullmatch(r"[0-9a-fA-F]{1,4}", host):          # no dots: a real IPv4 address or hostname never looks like this
        raise ConnectionBlockError("vnc.host", "That looks like an IPv6 address. IPv6 literals are not supported: use an IPv4 address or a hostname.")
    port, display = parse_vnc_address(match["addr"])
    user: str | None = None
    password: str | None = None
    consumed = [index]
    cursor = index + 1
    seen = 0
    while cursor < len(lines) and seen < 2:
        line = lines[cursor]
        if not line.strip():
            cursor += 1
            continue
        pw, usr = PASSWORD_LABEL.match(line), USER_LABEL.match(line)
        if pw and password is None:
            password = pw["value"].rstrip("\r\n")
        elif usr and user is None:
            user = usr["value"].strip()
        else:
            break
        consumed.append(cursor)
        seen += 1
        cursor += 1
    if password is None:
        raise ConnectionBlockError(
            "vnc.password",
            "A VNC connection needs a labelled password on the next line, for example 'password: ...'. "
            "An optional 'username: ...' line may come first. Nothing was sent to the model.")
    if not password.strip():
        raise ConnectionBlockError("vnc.password", "The VNC password after the 'password:' label is empty.")
    if CONTROL.search(password) or len(password) > 1024:
        raise ConnectionBlockError("vnc.password", "The VNC password contains control characters or is too long.")
    if len(password.encode("utf-8")) > MAX_VNC_PASSWORD_BYTES:
        raise ConnectionBlockError(
            "vnc.password",
            f"Classic VNC authentication uses at most {MAX_VNC_PASSWORD_BYTES} bytes of password; this one is longer. "
            "A longer password would be silently truncated by the server, so it is rejected instead.")
    if user is not None:
        if CREDENTIAL_LINE.match(user) or _labelled_secret_in(normalize_for_guard(user)) or "password" in user.lower().replace(" ", ""):
            raise ConnectionBlockError("vnc.user", "The username value looks like a password or another credential. Put only the account name after 'username:'.")
        if CONTROL.search(user) or len(user) > 256:
            raise ConnectionBlockError("vnc.user", "The VNC username contains control characters or is too long.")
        user = user or None
    return VncBlock(host=host, port=port, display=display, user=user, password=password, consumed=tuple(consumed))


def find_connection_lines(lines: list[str]) -> tuple[list[int], list[int]]:
    """(vnc_indexes, rdp_indexes) of lines that announce a connection."""
    vnc = [i for i, line in enumerate(lines) if VNC_LINE.search(line.strip())]
    rdp = [i for i, line in enumerate(lines) if RDP_LINE.search(line.strip())]
    return vnc, rdp


def unconsumed_credential_lines(lines: list[str], consumed: set[int]) -> list[int]:
    return [i for i, line in enumerate(lines) if i not in consumed and (CREDENTIAL_LINE.match(line) or URL_CREDENTIALS.search(line))]


_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0501": "d", "\u04bb": "h", "\u0391": "A", "\u0395": "E", "\u039f": "O", "\u03a1": "P", "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u0131": "i",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2212": "-", "\uff1a": ":", "\uff1d": "=", "\ufe55": ":", "\u2236": ":",
})
_LABEL = (r"(?:pass(?:word|wd|code|phrase)?s?|pwd|pw|pin|secret|token|credentials?|api[_ -]?key|bearer|private[_ -]?key"
          r"|kennwort|passwort|contrase[n\u00f1]a|clave|mot de passe|mdp|senha|wachtwoord|hasło|haslo|parola|l\u00f6senord|salasana|\u5bc6\u7801|\u30d1\u30b9\u30ef\u30fc\u30c9)")
_VALUE_STOPWORDS = frozenset(
    "field box prompt screen dialog page label text input is are was were be being appears appear shown visible masked hidden required empty blank "
    "manager reset policy change protected entry window form option setting settings column row below above here there not none n/a the a an".split())
LABELLED_VALUE = re.compile(r"(?i)(?<![A-Za-z0-9])" + _LABEL + r"(?![A-Za-z0-9])[\"']?\s*(?P<sep>[:=]|-|\bis\b)\s*[\"']?(?P<value>[^\s]+)")
LOGIN_AS_PAIR = re.compile(r"(?i)\b(?:log\s?in|sign\s?in|login|connect|ssh|rdp|vnc)\b[^\n]{0,60}?\bas\s+\S+\s*[/:]\s*\S{4,}")


def normalize_for_guard(text: str) -> str:
    """NFKC, drop zero-width/format characters, fold common look-alike letters and dash/colon variants, and join a label that was split from its
    separator by a line break ('password' newline ': x').  Line numbers are preserved for every other newline."""
    import unicodedata
    text = unicodedata.normalize("NFKC", text.replace("\r\n", "\n"))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.translate(_CONFUSABLES)
    return re.sub(r"(?i)(" + _LABEL + r")[ \t]*\n[ \t]*([:=])", r"\1\2", text)


def _labelled_secret_in(line: str) -> bool:
    for m in LABELLED_VALUE.finditer(line):
        sep, value = m.group("sep").lower(), m.group("value").strip("\"'.,;)").lower()
        if sep == "=":
            return True                                  # key=value is a credential assignment whatever the value looks like
        if not value or value in _VALUE_STOPWORDS:
            continue                                     # "Password: field", "password is required" - prose about a password, not one
        return True
    return False


def guard_texts(*texts) -> str | None:
    """First refusal message for any of the given free-text fields (None = all clear).  Used for EVERY string that may reach a model."""
    for text in texts:
        message = credential_guard_message(text)
        if message:
            return message
    return None


def credential_guard_message(text: str) -> str | None:
    """For text that is about to go to a MODEL: a refusal message if it carries connection credentials, else None.

    Refuses (a) any labelled credential (password:/pw=/'password is X'/passcode ..., after Unicode normalisation), (b) a URL with embedded user:password,
    (c) a recognised RDP/VNC connection line followed by two single-token lines (an unlabelled username + password).  It is a heuristic that reduces
    accidental disclosure; it cannot detect an unlabelled secret in free prose.
    """
    if not isinstance(text, str) or not text:
        return None
    lines = normalize_for_guard(text).splitlines()
    for number, line in enumerate(lines, 1):
        if CREDENTIAL_LINE.match(line) or _labelled_secret_in(line) or LOGIN_AS_PAIR.search(line):
            return (f"Line {number} looks like a credential. Credentials are never sent to the planning model: put the connection in the "
                    "'RDP to HOST' / 'VNC to HOST' block form (host line, then username and password lines) and use Build draft, "
                    "or remove the credential from the description.")
        if URL_CREDENTIALS.search(line):
            return (f"Line {number} contains a web address with an embedded user name and password. Remove it; credentials are never sent "
                    "to the planning model.")
    vnc, rdp = find_connection_lines(lines)
    for i in vnc + rdp:
        nonempty = [lines[j].strip() for j in range(i + 1, len(lines)) if lines[j].strip()][:4]
        for k in range(len(nonempty) - 1):                  # "username: bob" followed by one bare token = an unlabelled password
            if USER_LABEL.match(nonempty[k]) and re.fullmatch(r"\S{3,256}", nonempty[k + 1]) and not re.fullmatch(r"\d+[.)]?", nonempty[k + 1]):
                return (f"Line {i + 1} starts a connection block whose username line is followed by what looks like an unlabelled password. Use the local connection "
                        "intake (Build draft) with a 'password:' label; this text was not sent to the model.")
        following = nonempty[:2]
        if len(following) == 2 and all(2 <= len(item) <= 256 for item in following) and len(following[0].split()) <= 1 and len(following[1].split()) <= 2:
            return (f"Line {i + 1} starts a connection block with what looks like an unlabelled username and password. Use the local connection "
                    "intake (Build draft) with 'username:' and 'password:' labels; this text was not sent to the model.")
    return None
