"""Routes for VNC through SSH (simplified workspace).  Registered on the wizard router by wizard_routes.py.

Every route returns the same v2 public view as the other procedure routes (references and states only).  Request validation errors never echo
the submitted input, so a rejected password is not reflected back.  No route here starts a run, a process or a model call.
"""
from __future__ import annotations

from fastapi import Body, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import vnc_ssh
from .auth import verify_operator
from .wizard_routes import _target_service, router

_P = '/authoring/wizard/procedures/{key}'


def _ctx(request: Request):
    service = _target_service(request)
    return service, service.settings.wizard_state_root, service._secrets_root()


def _view(draft, secrets_root: str) -> dict:
    from .procedure_routes_v2 import _view as view_v2      # late import: procedure_routes_v2 may still be initialising
    return view_v2(draft, secrets_root)


def _fail(exc: vnc_ssh.VncSshError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={'errors': exc.errors})


@router.post('/authoring/wizard/vnc-ssh-procedures')
def create_vnc_ssh_procedure(request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from .target_setup import TargetSetupError
    service, state_root, secrets_root = _ctx(request)
    try:
        parsed = vnc_ssh.VncSshRequest.model_validate(body)
    except ValidationError as exc:
        errors = [{'field': '.'.join(str(p) for p in e['loc']), 'message': 'Invalid value.' if e['type'] != 'missing' else 'Required.'} for e in exc.errors()]
        return JSONResponse(status_code=422, content={'errors': errors})
    try:
        return _view(vnc_ssh.build_vnc_ssh_procedure(parsed, service, state_root), secrets_root)
    except vnc_ssh.VncSshError as exc:
        return _fail(exc)
    except TargetSetupError:
        return JSONResponse(status_code=422, content={'errors': [{'field': 'credential', 'message': 'A credential could not be saved; nothing was created.'}]})


@router.put(_P + '/gateway')
def update_vnc_ssh_gateway(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    from .target_setup import TargetSetupError
    service, state_root, secrets_root = _ctx(request)
    try:
        return _view(vnc_ssh.update_gateway(key, body, state_root, service), secrets_root)
    except vnc_ssh.VncSshError as exc:
        return _fail(exc)
    except TargetSetupError:
        return JSONResponse(status_code=422, content={'errors': [{'field': 'gateway.password', 'message': 'The password could not be saved; nothing was changed.'}]})


@router.post(_P + '/gateway/host-key/discover')
def discover_vnc_ssh_host_key(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    service, state_root, _s = _ctx(request)
    try:
        return vnc_ssh.discover_host_key(key, state_root, service.settings, body.get('confirmation') if isinstance(body, dict) else None)
    except vnc_ssh.VncSshError as exc:
        return _fail(exc)


@router.post(_P + '/gateway/host-key/approve')
def approve_vnc_ssh_host_key(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    service, state_root, secrets_root = _ctx(request)
    try:
        return _view(vnc_ssh.approve_host_key(key, state_root, service, body), secrets_root)
    except vnc_ssh.VncSshError as exc:
        return _fail(exc)


@router.post(_P + '/target-confirmation')
def confirm_vnc_ssh_target(key: str, request: Request, body: object = Body(...), _u=Depends(verify_operator)):
    _service, state_root, secrets_root = _ctx(request)
    try:
        return _view(vnc_ssh.confirm_target(key, state_root, body), secrets_root)
    except vnc_ssh.VncSshError as exc:
        return _fail(exc)
