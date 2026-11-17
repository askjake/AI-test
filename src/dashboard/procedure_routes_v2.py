"""NRDP-1 procedure v2 routes, registered on the existing wizard router.

Registration: wizard_routes.py must end with `from . import procedure_routes_v2  # noqa: E402,F401`
(see status S2a_01.md). Same prefix/auth idiom as the existing procedure routes.
"""
from __future__ import annotations

from fastapi import Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from .auth import verify_operator
from .wizard_routes import _target_service, router

_P = '/authoring/wizard/procedures/{key}'


def _ctx(request: Request):
    service = _target_service(request)
    return service, service.settings.wizard_state_root, service._secrets_root()


def _load(key: str, state_root: str):
    from .procedure_intake import IntakeError, load_procedure
    try:
        return load_procedure(key, state_root)
    except IntakeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None


def _view(draft, secrets_root: str) -> dict:
    from .procedure_intake import public_view
    from . import procedure_runs
    view = public_view(draft, secrets_root)
    # The run surface must reflect what the backend will actually start, so the UI cannot offer a
    # mode the API would refuse (connection-only qualification).
    view["run_capability"] = procedure_runs.capability()
    return view


@router.get(_P + '/view')
def read_full_procedure_v2(key: str, request: Request, _u=Depends(verify_operator)):
    """v2 public view (credential state + readiness). The legacy GET stays unchanged for compatibility."""
    _service, state_root, secrets_root = _ctx(request)
    return _view(_load(key, state_root), secrets_root)


@router.put(_P + '/connections')
def update_procedure_connections(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from pydantic import SecretStr
    from .procedure_intake import ConnectionEditError, IntakeError, update_connections
    from .target_setup import TargetSetupError
    service, state_root, secrets_root = _ctx(request)
    _load(key, state_root)
    edits = body.get('connections') if isinstance(body, dict) else None
    if not isinstance(edits, list):
        return JSONResponse(status_code=422, content={'errors': [{'field': 'connections', 'message': 'Provide a connections list.'}]})
    edits = [_normalise_edit(e) for e in edits]
    edits = [dict(e, new_password=SecretStr(e['new_password'])) if isinstance(e, dict) and isinstance(e.get('new_password'), str) and e['new_password'] else
             {k: v for k, v in e.items() if k != 'new_password'} if isinstance(e, dict) else e
             for e in edits]
    try:
        draft = update_connections(key, edits, state_root, service)
    except ConnectionEditError as exc:
        return JSONResponse(status_code=422, content={'errors': exc.errors})
    except (IntakeError, TargetSetupError) as exc:
        return JSONResponse(status_code=422, content={'errors': [{'field': 'connections', 'message': str(exc)}]})
    return _view(draft, secrets_root)


def _normalise_edit(edit):
    """Accept the UI's nested ``certificate: {name, fingerprint}`` as the flat certificate_* keys."""
    if not isinstance(edit, dict):
        return edit
    out = dict(edit)
    cert = out.pop('certificate', None)
    if isinstance(cert, dict):
        if 'name' in cert:
            out.setdefault('certificate_name', cert.get('name'))
        if 'fingerprint' in cert:
            out.setdefault('certificate_fingerprint', cert.get('fingerprint'))
    return out


@router.post(_P + '/connections/{order}/certificate/probe')
def probe_procedure_certificate(key: str, order: int, request: Request, _u=Depends(verify_operator)):
    from . import rdp_cert_probe
    from .procedure_intake import normalise_fingerprint
    _service, state_root, _secrets_root = _ctx(request)
    draft = _load(key, state_root)
    if order != 1:
        raise HTTPException(status_code=422, detail='Certificate probing applies to hop 1 only.')
    hop = draft.connections[0]
    try:
        result = rdp_cert_probe.probe_rdp_certificate(hop.host, hop.port)
    except rdp_cert_probe.RdpProbeBusy as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=502, detail='The RDP certificate could not be read from the dashboard host.') from None
    name = result.get('name') if isinstance(result, dict) else getattr(result, 'name', None)
    fp = result.get('fingerprint') if isinstance(result, dict) else getattr(result, 'fingerprint', None)
    fp = normalise_fingerprint(fp) if isinstance(fp, str) else None
    if not name or not fp:
        raise HTTPException(status_code=502, detail='The RDP certificate probe returned no usable name or fingerprint.')
    return {'name': name, 'fingerprint': fp, 'source': 'dashboard-host probe'}  # never persisted


@router.post('/authoring/wizard/rdp-certificate/probe')
def probe_builder_rdp_certificate(request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    """Connection Builder: read the hop-1 RDP certificate BEFORE the draft is saved.  Same safeguards as the saved-draft probe (one probe at a
    time, one deadline, loopback/link-local/reserved refused, no credentials sent, nothing persisted); the host and port are the builder's hop 1."""
    from . import rdp_cert_probe
    from .procedure_intake import normalise_fingerprint
    if not isinstance(body, dict) or set(body) - {'host', 'port'}:
        raise HTTPException(status_code=422, detail='Provide only the hop 1 host and port.')
    host, port = body.get('host'), body.get('port')
    if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
        raise HTTPException(status_code=422, detail='Provide the hop 1 host and a numeric port.')
    try:
        result = rdp_cert_probe.probe_rdp_certificate(host.strip(), port)
    except rdp_cert_probe.RdpProbeBusy as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=502, detail='The RDP certificate could not be read from the dashboard host.') from None
    name = result.get('name') if isinstance(result, dict) else getattr(result, 'name', None)
    fp = result.get('fingerprint') if isinstance(result, dict) else getattr(result, 'fingerprint', None)
    fp = normalise_fingerprint(fp) if isinstance(fp, str) else None
    if not name or not fp:
        raise HTTPException(status_code=502, detail='The RDP certificate probe returned no usable name or fingerprint.')
    return {'name': name, 'fingerprint': fp, 'source': 'dashboard-host probe'}  # never persisted


def _gateway_gate(draft):
    """VNC through SSH: the project and any run need an approved gateway host key and a confirmation of the CURRENT settings."""
    gw = getattr(draft, 'gateway', None)
    if gw is None:
        return None
    from .procedure_intake import connection_config_hash
    if not (gw.known_hosts_reference and gw.host_key_fingerprint):
        return 'Approve the SSH gateway host key first.'
    if (getattr(draft, 'target_confirmation', None) or {}).get('config_hash') != connection_config_hash(draft):
        return 'Confirm the gateway, destination and account for the current settings first.'
    return None


@router.post(_P + '/project')
def create_procedure_project(key: str, request: Request, body: object = Body(default=None), _u=Depends(verify_operator)):
    from . import procedure_project
    from .procedure_intake import persist_draft
    service, state_root, secrets_root = _ctx(request)
    draft = _load(key, state_root)
    gate = _gateway_gate(draft)
    if gate:
        return JSONResponse(status_code=409, content={'errors': [{'field': 'gateway', 'message': gate}]})
    replace = bool(body.get('replace')) if isinstance(body, dict) else False
    try:
        result = procedure_project.create_project(draft, specs_root=service.settings.specs_dir, secrets_root=secrets_root, replace=replace)
    except procedure_project.ProjectError as exc:
        return JSONResponse(status_code=422, content={'errors': exc.errors})
    import datetime as _dt
    from .procedure_intake import connection_config_hash
    persist_draft(key, state_root, draft.model_copy(update={'project': {
        'project_name': result['project_name'],
        'name': result['project_name'],
        'config_hash': connection_config_hash(draft),   # the connections this project was built from
        'created_at': _dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}}))
    return result


def _run_error(exc):
    return HTTPException(status_code=getattr(exc, 'status_code', 422) or 422, detail=str(getattr(exc, 'message', exc)))


def _project_name(draft) -> str:
    name = (draft.project or {}).get('project_name')
    if not name:
        raise HTTPException(status_code=409, detail='Create the project before running this procedure.')
    return name


@router.post(_P + '/runs')
def start_procedure_run(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from . import procedure_runs
    _service, state_root, _s = _ctx(request)
    draft = _load(key, state_root)
    if not isinstance(body, dict) or not isinstance(body.get('mode'), str):
        raise HTTPException(status_code=422, detail='Provide a run mode.')
    phrase = body.get('confirm_phrase')
    gate = _gateway_gate(draft)
    if gate:
        raise HTTPException(status_code=409, detail=gate)
    from .procedure_intake import connection_config_hash
    cfg = connection_config_hash(draft)
    try:
        if body['mode'] in procedure_runs.MODES:
            procedure_runs.check_preconditions(project=draft.project, last_test=draft.last_test,
                                               config_hash=cfg, mode=body['mode'])
        return procedure_runs.start_run(draft, _project_name(draft), body['mode'], phrase if isinstance(phrase, str) else None,
                                        config_hash=cfg, leave_open_ack=body.get('leave_open_ack'), url=body.get('url'))
    except procedure_runs.RunError as exc:
        raise _run_error(exc) from None


@router.get(_P + '/runs/{run_id}')
def get_procedure_run(key: str, run_id: str, request: Request, _u=Depends(verify_operator)):
    from . import procedure_runs
    _service, state_root, _s = _ctx(request)
    try:
        draft = _load(key, state_root)
        out = procedure_runs.get_run(_project_name(draft), run_id)
    except procedure_runs.RunError as exc:
        raise _run_error(exc) from None
    _record_last_test(key, state_root, draft, out)
    out.pop('config_hash', None)
    return out


_TEST_DONE = {'complete', 'completed', 'passed', 'succeeded', 'failed', 'error', 'errored', 'incomplete', 'cancelled', 'timeout', 'blocked'}


def _record_last_test(key: str, state_root: str, draft, out: dict) -> None:
    """Server-side record of the last connection test, bound to the connections it was started with.

    Only an honest connection test counts (requested AND effective mode are connection_test); a
    downgraded run never becomes the test a full run is allowed to rely on.
    """
    from .procedure_intake import persist_draft
    import datetime as _dt
    if out.get('requested_mode') != 'connection_test' or out.get('effective_mode') != 'connection_test' or out.get('downgraded'):
        return
    state = str(out.get('state', '')).lower()
    if state not in _TEST_DONE or (draft.last_test or {}).get('run_id') == out.get('run_id'):
        return
    result = (out.get('status_detail') or {}).get('result')
    status = 'passed' if (state in ('complete', 'completed', 'passed', 'succeeded') and result in (None, 'passed')) else 'failed'
    persist_draft(key, state_root, draft.model_copy(update={'last_test': {
        'run_id': out.get('run_id'), 'mode': 'connection_test', 'status': status, 'config_hash': out.get('config_hash'),
        'at': _dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}}))


@router.post(_P + '/runs/{run_id}/cancel')
def cancel_procedure_run(key: str, run_id: str, request: Request, _u=Depends(verify_operator)):
    from . import procedure_runs
    _service, state_root, _s = _ctx(request)
    try:
        return procedure_runs.cancel_run(_project_name(_load(key, state_root)), run_id)
    except procedure_runs.RunError as exc:
        raise _run_error(exc) from None


@router.post(_P + '/runs/{run_id}/checkpoint')
def ack_procedure_checkpoint(key: str, run_id: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from . import procedure_runs
    _service, state_root, _s = _ctx(request)
    if not isinstance(body, dict) or not isinstance(body.get('id'), str):
        raise HTTPException(status_code=422, detail='Provide the checkpoint id.')
    note = body.get('note') if isinstance(body.get('note'), str) else None
    try:
        return procedure_runs.ack_checkpoint(_project_name(_load(key, state_root)), run_id, body['id'], note)
    except procedure_runs.RunError as exc:
        raise _run_error(exc) from None
