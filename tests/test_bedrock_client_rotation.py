"""Runner-side Bedrock client with the refresh-aware coordinator.  Fictional credentials; the network is short-circuited at before-send."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from aws_refresh import reset_registry
from orchestrator.bedrock_client import BedrockClient, BedrockCredentialError, BedrockError
from tests.test_aws_refresh import NEW, OLD, SECRETS, body, no_secrets, write_atomic

RESPONSE = {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}}


def staged(tmp_path, monkeypatch, creds, expires_in=3000):
    reset_registry()
    path = tmp_path / "runtime-credentials"
    write_atomic(str(path), body(creds, expires_in))
    os.utime(path, (time.time() - 5, time.time() - 5))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))
    monkeypatch.setenv("AWS_PROFILE", "default")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    return path


def instrument(client, seen, expired_for):
    from botocore.awsrequest import AWSResponse

    class Raw:
        def __init__(self, data):
            self._d = data

        def stream(self, **_):
            yield self._d

        def read(self, *_):
            return self._d

    def handler(request, **_):
        auth = request.headers.get("Authorization", b"")
        auth = auth.decode() if isinstance(auth, bytes) else auth
        key = auth.split("Credential=")[1].split("/")[0]
        seen.append(key)
        if key in expired_for:
            return AWSResponse(request.url, 400, {"x-amzn-ErrorType": "ExpiredTokenException", "Content-Type": "application/json"},
                               Raw(json.dumps({"message": "The security token included in the request is expired"}).encode()))
        return AWSResponse(request.url, 200, {"Content-Type": "application/json"}, Raw(json.dumps(RESPONSE).encode()))

    client._client.meta.events.register("before-send.bedrock-runtime.InvokeModel", handler)


def call(client):
    return client.invoke(messages=[{"role": "user", "content": "x"}], tools=[])


@pytest.fixture(autouse=True)
def _region(monkeypatch):
    from orchestrator.config import settings
    monkeypatch.setattr(settings, "aws_region", "us-west-2")


def test_a_rotation_during_a_running_job_reaches_the_next_model_call(tmp_path, monkeypatch):
    path = staged(tmp_path, monkeypatch, OLD)
    client = BedrockClient(model_id="m", base_backoff=0.0)
    seen = []
    instrument(client, seen, expired_for=())
    client._coordinator._min_interval = 0.0                                          # production default is 0.5 s between stat() checks
    call(client)
    write_atomic(str(path), body(NEW, 3000))                                       # the credential bridge replaced the staged file
    call(client)
    assert seen == [OLD[0], NEW[0]]                                                 # same client object, no restart, no rebuild


def test_expired_credentials_trigger_one_reload_and_one_retry_of_the_model_call_only(tmp_path, monkeypatch):
    path = staged(tmp_path, monkeypatch, OLD)
    client = BedrockClient(model_id="m", base_backoff=0.0)
    seen = []
    instrument(client, seen, expired_for=(OLD[0],))
    client._coordinator._min_interval = 1e9                                         # the process has not looked at the file since it loaded it
    client._coordinator.current()
    write_atomic(str(path), body(NEW, 3000))
    actions = []                                                                    # stands for desktop actions that must never be replayed
    result = call(client)
    assert result is not None and seen == [OLD[0], NEW[0]] and actions == []


def test_expired_and_never_renewed_raises_a_distinct_error_after_exactly_one_request(tmp_path, monkeypatch):
    staged(tmp_path, monkeypatch, OLD, expires_in=-4000)
    client = BedrockClient(model_id="m", base_backoff=0.0)
    seen = []
    instrument(client, seen, expired_for=(OLD[0],))
    with pytest.raises(BedrockCredentialError) as err:
        call(client)
    assert len(seen) == 1 and err.value.category == "upstream_renewal_failed" and "cannot renew a human login" in str(err.value)
    no_secrets(err.value, repr(err.value))


def test_other_client_errors_are_not_treated_as_expired_and_are_not_retried(tmp_path, monkeypatch):
    staged(tmp_path, monkeypatch, OLD)
    client = BedrockClient(model_id="m", base_backoff=0.0)
    seen = []
    from botocore.awsrequest import AWSResponse

    class Raw:
        def stream(self, **_):
            yield b'{"message": "denied"}'

        def read(self, *_):
            return b'{"message": "denied"}'

    client._client.meta.events.register("before-send.bedrock-runtime.InvokeModel", lambda request, **_: seen.append(1) or AWSResponse(
        request.url, 403, {"x-amzn-ErrorType": "AccessDeniedException"}, Raw()))
    with pytest.raises(BedrockError) as err:
        call(client)
    assert len(seen) == 1 and not isinstance(err.value, BedrockCredentialError)


def test_without_a_staged_file_the_previous_behaviour_remains_and_the_retry_is_still_bounded(monkeypatch):
    monkeypatch.delenv("AWS_SHARED_CREDENTIALS_FILE", raising=False)
    from tests.test_bedrock_client import FakeClient, _client_error
    clients = iter([FakeClient(errors=[_client_error("ExpiredTokenException")] * 3) for _ in range(5)])
    created = []

    def factory():
        c = next(clients)
        created.append(c)
        return c

    client = BedrockClient(client_factory=factory, model_id="m", base_backoff=0.0)
    with pytest.raises(BedrockError):
        call(client)
    assert len(created) == 2 and client._coordinator is None                         # one initial client + exactly one rebuild


# ---------------------------------------------------------------------------------------------- host file -> bridge -> running job
@pytest.mark.skipif(os.name != "posix", reason="the runner's credential bridge is POSIX-only (pwd, uid/gid, 0400 files)")
def test_rotation_on_the_host_reaches_the_next_model_call_of_a_running_job_through_the_real_bridge(tmp_path, monkeypatch):
    """host credentials file (atomically replaced, new inode)  ->  orchestrator.credential_sync (the container's root bridge)
    ->  staged private copy  ->  BedrockClient inside the running job.  The job object is never rebuilt."""
    from orchestrator import credential_sync
    reset_registry()
    host = tmp_path / "host"
    host.mkdir()
    source = host / "credentials"
    write_atomic(str(source), body(OLD, 3000))
    os.utime(source, (time.time() - 5, time.time() - 5))
    runtime = tmp_path / "runtime"
    uid, gid = os.getuid(), os.getgid()
    _count, signatures = credential_sync.sync_once(str(source), str(runtime), uid=uid, gid=gid)
    staged_file = runtime / "credentials"
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(staged_file))
    monkeypatch.setenv("AWS_PROFILE", "default")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    job = BedrockClient(model_id="m", base_backoff=0.0)
    job._coordinator._min_interval = 0.0
    job._coordinator._settle = 0.0
    seen = []
    instrument(job, seen, expired_for=())
    call(job)
    first_inode = os.stat(staged_file).st_ino
    replacement = host / "credentials.new"
    write_atomic(str(replacement), body(NEW, 3000))
    os.utime(replacement, (time.time() - 5, time.time() - 5))
    os.replace(replacement, source)                                                  # an external refresher's atomic replacement
    count, signatures = credential_sync.sync_once(str(source), str(runtime), uid=uid, gid=gid, previous=signatures)
    assert count == 1 and os.stat(staged_file).st_ino != first_inode                  # the bridge published a new inode
    call(job)                                                                        # the SAME running job object
    assert seen == [OLD[0], NEW[0]]


@pytest.mark.skipif(os.name != "posix", reason="the runner's credential bridge is POSIX-only")
def test_the_bridge_never_hands_the_job_a_half_written_source(tmp_path, monkeypatch):
    from orchestrator import credential_sync
    reset_registry()
    host = tmp_path / "host"
    host.mkdir()
    source = host / "credentials"
    write_atomic(str(source), body(OLD, 3000))
    runtime = tmp_path / "runtime"
    uid, gid = os.getuid(), os.getgid()
    _c, signatures = credential_sync.sync_once(str(source), str(runtime), uid=uid, gid=gid)
    with open(source, "w") as handle:                                                 # a non-atomic writer, caught mid-write
        handle.write("[default]\naws_access_key_id = " + NEW[0] + "\naws_secret_access_key = " + NEW[1][:10])
    count, signatures = credential_sync.sync_once(str(source), str(runtime), uid=uid, gid=gid, previous=signatures, settle_seconds=5.0)
    assert count == 0                                                                 # postponed: the file is too fresh to copy
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(runtime / "credentials"))
    monkeypatch.setenv("AWS_PROFILE", "default")
    job = BedrockClient(model_id="m", base_backoff=0.0)
    seen = []
    instrument(job, seen, expired_for=())
    call(job)
    assert seen == [OLD[0]]                                                           # still the last good credentials


@pytest.mark.parametrize("code", ["InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "AccessDeniedException", "ThrottlingException"])
def test_invalid_or_denied_credentials_are_not_treated_as_expired_and_are_not_retried(code, tmp_path, monkeypatch):
    from tests.test_bedrock_client import FakeClient, _client_error
    created = []

    def factory():
        c = FakeClient(errors=[_client_error(code)] * 3)
        created.append(c)
        return c

    client = BedrockClient(client_factory=factory, model_id="m", base_backoff=0.0, max_retries=0)
    with pytest.raises(BedrockError):
        call(client)
    assert len(created) == 1 and len(created[0].calls) == 1          # no rebuild, no second request


def test_error_text_carries_code_and_request_id_but_never_the_service_message():
    from tests.test_bedrock_client import FakeClient, _client_error
    secret_echo = "PROMPT-FRAGMENT-SHOULD-NOT-APPEAR AKIAFAKEFRAGMENT"
    client = BedrockClient(client=FakeClient(errors=[_client_error("InternalServerException", secret_echo)]), model_id="m", base_backoff=0.0, max_retries=0)
    with pytest.raises(BedrockError) as err:
        call(client)
    assert "InternalServerException" in str(err.value) and "PROMPT-FRAGMENT" not in str(err.value) and "AKIAFAKEFRAGMENT" not in str(err.value)
