"""In-process offline API bridge for the localhost browser gate only."""
import json
import os
from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient
from dashboard.auth import verify_operator
from dashboard.config import DashboardSettings
from dashboard.target_probe import TargetProbeService
from dashboard.wizard_routes import router as wizard_router
from dashboard.editor_routes import router as editor_router


def forbidden(*_args, **_kwargs):
    raise AssertionError('Target or process activity forbidden in browser gate')


root = Path(sys.argv[1])
for key, sub in [('DASHBOARD_SPECS_DIR','specs'),('TESTS_SPECS_DIR','specs'),
                 ('TESTS_MANUALS_DIR','manuals'),('DASHBOARD_REPORTS_DIR','reports'),
                 ('DASHBOARD_SECRETS_DIR','secrets')]:
    os.environ[key] = str(root/sub)
secret_dir=root/'secrets';secret_dir.mkdir(mode=0o700,exist_ok=True)
for name in ['desktop.rdp.pw','desktop.vncpass','gateway.pw','jump.hosts']:
    p=secret_dir/name
    if not p.exists(): p.write_text('DUMMY-OFFLINE-FIXTURE\n');p.chmod(0o600)
settings=DashboardSettings(auth_token='viewer',auth_operator_token='operator',
    specs_dir=str(root/'specs'),reports_dir=str(root/'reports'),secrets_dir=str(secret_dir))
app=FastAPI();app.dependency_overrides[verify_operator]=lambda:'operator'
app.state.target_probe_service=TargetProbeService(settings,connector=forbidden,
    popen_factory=forbidden,which=lambda _:None)
app.include_router(wizard_router,prefix='/api/v1');app.include_router(editor_router,prefix='/api/v1')
data=json.load(sys.stdin)
allowed={'/api/v1/authoring/wizard/review','/api/v1/authoring/wizard/readiness',
         '/api/v1/authoring/wizard/validate','/api/v1/projects/authoring'}
if data['path'] not in allowed: raise AssertionError('Unexpected offline bridge route')
with TestClient(app) as client:
    result=client.post(data['path'],json=data['body'])
    print(json.dumps({'status':result.status_code,'body':result.json()}))
