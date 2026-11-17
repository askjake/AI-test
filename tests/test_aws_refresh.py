"""AWS refresh-aware credential handling.  Fictional credentials only.

Labels: the botocore tests use the REAL botocore signer and a real boto3 client object with the network short-circuited at ``before-send``
(no AWS contact); everything else is pure.  None of this calls Bedrock.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from aws_refresh import (Coordinator, CredentialsStillExpired, UpstreamRenewalFailed, classify_error, get_coordinator, read_options, reset_registry)
from aws_refresh import coordinator as coord_module
from aws_refresh.source import SourceError, load_credentials, parse_expiry

SECRETS = ("FAKEFICTIONALOLD0001", "fictional/secret/OLD/0123456789abcdefghijklmnopqrstuv", "fictional-token-OLD-" + "x" * 50,
           "FAKEFICTIONALNEW0002", "fictional/secret/NEW/0123456789abcdefghijklmnopqrstuv", "fictional-token-NEW-" + "y" * 50)
OLD = SECRETS[:3]
NEW = SECRETS[3:]


def stamp(delta):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def body(creds, expires_in, profile="default", extra=""):
    k, s, t = creds
    return f"[other]\naws_access_key_id = FAKEOTHERPROFILE00000\naws_secret_access_key = other-secret-{'z' * 30}\n\n[{profile}]\naws_access_key_id = {k}\naws_secret_access_key = {s}\naws_session_token = {t}\nexpiration = {stamp(expires_in)}\n{extra}"


def write_atomic(path, text):
    tmp = f"{path}.tmp{time.monotonic_ns()}"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


@pytest.fixture
def src(tmp_path):
    reset_registry()
    p = tmp_path / "credentials"
    write_atomic(str(p), body(OLD, 3000))
    return p


def make(src, **kw):
    kw.setdefault("min_check_interval", 0.0)
    kw.setdefault("settle_seconds", 0.0)
    return Coordinator(str(src), "default", region="us-west-2", **kw)


def expired_error(code="ExpiredTokenException"):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": "The security token included in the request is expired"}}, "InvokeModel")


def client_error(code, message="x"):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": message}}, "InvokeModel")


def no_secrets(*texts):
    blob = "\n".join(str(t) for t in texts)
    for secret in SECRETS:
        assert secret not in blob


# ------------------------------------------------------------------------------------------------ source
def test_a_complete_profile_loads_and_other_profiles_are_never_touched(src):
    before = src.read_bytes()
    loaded = load_credentials(str(src), "default", settle_seconds=0)
    assert (loaded.access_key, loaded.token) == (OLD[0], OLD[2]) and loaded.expiry is not None
    assert src.read_bytes() == before                                   # read-only: the unrelated [other] profile is untouched


@pytest.mark.parametrize("text,code", [
    ("[default]\naws_access_key_id = AKIAX\n", "incomplete"),
    ("[default]\naws_access_key_id = AKIAX\naws_secret_access_key = s\naws_session_token =\n", "incomplete"),
    ("[nothere]\naws_access_key_id = a\naws_secret_access_key = b\n", "profile_missing"),
    ("[default]\nregion = us-west-2\n", "no_static_keys"),
    ("this is not an ini file", "incomplete"),
])
def test_incomplete_or_unusable_files_are_rejected_with_a_stable_code(tmp_path, text, code):
    p = tmp_path / "c"
    p.write_text(text)
    with pytest.raises(SourceError) as err:
        load_credentials(str(p), "default", settle_seconds=0)
    assert err.value.code == code and "AKIAX" not in err.value.message


def test_expiry_markers_in_several_common_forms():
    for value in ("2030-01-02T03:04:05Z", "2030-01-02 03:04:05+00:00", "2030-01-02T03:04:05", "1893553445"):
        assert parse_expiry(value) is not None
    assert parse_expiry("garbage") is None and parse_expiry("") is None


# ------------------------------------------------------------------------------------------------ rotation
def test_atomic_replacement_with_a_new_inode_is_detected_without_restart(src):
    c = make(src)
    first = c.current()
    inode = os.stat(src).st_ino
    write_atomic(str(src), body(NEW, 3000))
    assert os.stat(src).st_ino != inode or True                            # inode usually changes; the signature also covers mtime and size
    second = c.current()
    assert (first.access_key, second.access_key) == (OLD[0], NEW[0]) and c.generation == 2 and c.change_count == 2


def test_an_in_place_rewrite_is_detected_through_mtime(src):
    c = make(src)
    c.current()
    time.sleep(0.02)
    with open(src, "w") as fh:
        fh.write(body(NEW, 3000))
    assert c.current().access_key == NEW[0]


def test_a_partially_written_file_is_never_used_and_the_previous_good_credentials_stay(src):
    c = make(src)
    assert c.current().access_key == OLD[0]
    full = body(NEW, 3000)
    with open(src, "w") as fh:                                               # non-atomic writer caught mid-write: token key present but empty
        fh.write(full.split("aws_session_token")[0] + "aws_session_token =")
    still = c.current()
    assert still.access_key == OLD[0] and c.last_failure["code"] == "incomplete"
    write_atomic(str(src), full)
    assert c.current().access_key == NEW[0] and c.last_failure is None


def test_a_file_replaced_by_one_that_lost_its_token_is_not_used(src):
    c = make(src)
    c.current()
    write_atomic(str(src), f"[default]\naws_access_key_id = {NEW[0]}\naws_secret_access_key = {NEW[1]}\n")
    assert c.current().access_key == OLD[0] and "token" in c.last_failure["message"]


def test_a_vanished_file_keeps_unexpired_credentials_but_fails_clearly_once_expired(src):
    c = make(src)
    c.current()
    os.unlink(src)
    assert c.current().access_key == OLD[0] and c.last_failure["code"] == "missing"
    write_atomic(str(src), body(OLD, -50))                                   # a different expired set arrives, then the file disappears
    c2 = make(src)
    c2.current()
    os.unlink(src)
    with pytest.raises(Exception) as err:
        c2.current()
    assert err.value.category == "source_error"


def test_a_recently_written_file_is_given_a_moment_to_settle(src):
    slept = []
    c = Coordinator(str(src), "default", min_check_interval=0.0, settle_seconds=5.0, sleep=lambda s: slept.append(s))
    write_atomic(str(src), body(NEW, 3000))
    try:
        c.current()
    except Exception:
        pass
    assert slept, "a file modified within the settle window must not be read immediately"


# ------------------------------------------------------------------------------------------------ classification
@pytest.mark.parametrize("code,expected", [
    ("ExpiredTokenException", "expired_token"), ("ExpiredToken", "expired_token"), ("RequestExpired", "expired_token"),
    ("AccessDeniedException", "access_denied"), ("UnrecognizedClientException", "invalid_credentials"),
    ("ThrottlingException", "throttled"), ("ValidationException", "model_request"), ("ResourceNotFoundException", "model_config"),
    ("InternalServerException", "unknown"), ("ServiceUnavailableException", "unknown"),
])
def test_only_definite_expiry_codes_are_expired(code, expected):
    assert classify_error(client_error(code)) == expected


def test_a_bare_403_a_timeout_and_a_schema_error_are_not_expired_tokens():
    from botocore.exceptions import ConnectTimeoutError, NoCredentialsError, ReadTimeoutError
    assert classify_error(client_error("403")) == "unknown"
    assert classify_error(ReadTimeoutError(endpoint_url="https://x")) == "network"
    assert classify_error(ConnectTimeoutError(endpoint_url="https://x")) == "network"
    assert classify_error(NoCredentialsError()) == "no_credentials"
    assert classify_error(ValueError("schema")) == "unknown"
    assert classify_error(client_error("ValidationException", "bad schema")) == "model_request"


# ------------------------------------------------------------------------------------------------ bounded retry
def test_expired_then_rotated_succeeds_with_exactly_one_retry(src):
    c = make(src, min_check_interval=1e9)
    c.current()
    calls = []

    def fn():
        calls.append(c.current().access_key)
        if calls[-1] == OLD[0]:
            raise expired_error()
        return "ok"

    write_atomic(str(src), body(NEW, 3000))                               # the external helper rotated the file; the cached view is still the old one
    assert c.call(fn) == "ok" and calls == [OLD[0], NEW[0]]


def test_expired_and_not_renewed_reports_upstream_renewal_failed_after_one_call(src):
    write_atomic(str(src), body(OLD, -500))
    c = make(src, min_check_interval=1e9)
    c.current()
    calls = []

    def fn():
        calls.append(1)
        raise expired_error()

    with pytest.raises(UpstreamRenewalFailed) as err:
        c.call(fn)
    assert calls == [1] and err.value.category == "upstream_renewal_failed" and "not been renewed" in str(err.value) and "cannot renew a human login" in str(err.value)
    no_secrets(err.value, err.value.details, c.status())


def test_a_reload_that_yields_still_expired_credentials_is_not_retried(src):
    c = make(src, min_check_interval=1e9)
    c.current()
    write_atomic(str(src), body(NEW, -100))                               # rotated, but to another EXPIRED set
    calls = []

    def fn():
        calls.append(1)
        raise expired_error()

    with pytest.raises(UpstreamRenewalFailed):
        c.call(fn)
    assert calls == [1]


def test_the_retry_is_never_repeated(src):
    c = make(src, min_check_interval=1e9)
    c.current()
    write_atomic(str(src), body(NEW, 3000))
    calls = []

    def fn():
        calls.append(1)
        raise expired_error()                                                  # the service keeps rejecting even the new credentials

    with pytest.raises(CredentialsStillExpired):
        c.call(fn)
    assert len(calls) == 2


@pytest.mark.parametrize("error", [lambda: client_error("AccessDeniedException"), lambda: client_error("ThrottlingException"),
                                   lambda: client_error("ValidationException", "schema"), lambda: client_error("ResourceNotFoundException"),
                                   lambda: client_error("UnrecognizedClientException"), lambda: RuntimeError("boom"), lambda: TimeoutError("t"),
                                   lambda: client_error("403")])
def test_non_expiry_errors_do_not_reload_and_are_not_retried(src, error, monkeypatch):
    c = make(src, min_check_interval=1e9)
    c.current()
    loads = []
    real = coord_module.load_credentials
    monkeypatch.setattr(coord_module, "load_credentials", lambda *a, **k: loads.append(1) or real(*a, **k))
    calls = []

    def fn():
        calls.append(1)
        raise error()

    with pytest.raises(Exception):
        c.call(fn)
    assert calls == [1] and loads == []


def test_concurrent_expired_failures_cause_one_coordinated_reload(src, monkeypatch):
    c = make(src, min_check_interval=1e9)
    c.current()
    write_atomic(str(src), body(NEW, 3000))
    loads = []
    real = coord_module.load_credentials
    monkeypatch.setattr(coord_module, "load_credentials", lambda *a, **k: loads.append(1) or real(*a, **k))
    barrier, results = threading.Barrier(8), []

    def worker():
        barrier.wait()

        def fn():
            if c.current().access_key == OLD[0]:
                raise expired_error()
            return "ok"
        results.append(c.call(fn))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert results == ["ok"] * 8 and len(loads) == 1 and c.generation == 2


def test_concurrent_failures_with_a_stale_source_also_reload_only_once(src, monkeypatch):
    write_atomic(str(src), body(OLD, -500))
    c = make(src, min_check_interval=1e9)
    c.current()
    loads = []
    real = coord_module.load_credentials
    monkeypatch.setattr(coord_module, "load_credentials", lambda *a, **k: loads.append(1) or real(*a, **k))
    barrier, outcomes = threading.Barrier(8), []

    def worker():
        barrier.wait()
        try:
            c.call(lambda: (_ for _ in ()).throw(expired_error()))
        except UpstreamRenewalFailed as exc:
            outcomes.append(exc.category)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    assert outcomes == ["upstream_renewal_failed"] * 8 and len(loads) == 1


# ------------------------------------------------------------------------------------------------ real botocore signing
def build_client(c, seen):
    """A real bedrock-runtime client (real signer); the network is short-circuited at before-send and answers by the key that signed."""
    from botocore.awsrequest import AWSResponse
    from botocore.config import Config
    client = c.client("bedrock-runtime", config=Config(retries={"max_attempts": 0}))

    class Raw:
        def __init__(self, data):
            self._d = data
            self.status_code = 0

        def stream(self, **_):
            yield self._d

        def read(self, *_):
            return self._d

    def handler(request, **_):
        auth = request.headers.get("Authorization", b"")
        auth = auth.decode() if isinstance(auth, bytes) else auth
        key = auth.split("Credential=")[1].split("/")[0]
        seen.append(key)
        if key == OLD[0] and expired_keys:
            data = json.dumps({"message": "The security token included in the request is expired"}).encode()
            resp = AWSResponse(request.url, 400, {"x-amzn-ErrorType": "ExpiredTokenException", "Content-Type": "application/json"}, Raw(data))
        else:
            resp = AWSResponse(request.url, 200, {"Content-Type": "application/json"}, Raw(b'{"ok": true}'))
        return resp

    client.meta.events.register("before-send.bedrock-runtime.InvokeModel", handler)
    return client


expired_keys = True


def invoke(client):
    return client.invoke_model(modelId="m", body=b"{}", contentType="application/json", accept="application/json")


def test_a_persistent_real_client_signs_with_rotated_credentials_without_being_rebuilt(src, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "FAKEENVIRONMENTSHOULDLOSE")       # inherited environment credentials must not win
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    c = make(src)
    seen = []
    client = build_client(c, seen)
    monkeypatch.setitem(globals(), "expired_keys", False)
    invoke(client)
    write_atomic(str(src), body(NEW, 3000))                                    # rotation WHILE the job is running: the same client object
    invoke(client)
    assert seen == [OLD[0], NEW[0]]


def test_expired_credentials_on_a_persistent_client_recover_after_one_coordinated_reload(src, monkeypatch):
    monkeypatch.setitem(globals(), "expired_keys", True)
    c = make(src, min_check_interval=1e9)
    seen = []
    client = build_client(c, seen)
    c.current()
    write_atomic(str(src), body(NEW, 3000))                                    # the helper renewed the file; this process has not looked yet
    result = c.call(lambda: invoke(client))                                      # first send is rejected as expired, then reload, then ONE retry
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200 and seen == [OLD[0], NEW[0]]


def test_error_text_from_a_real_rejection_carries_no_credential_values(src, monkeypatch):
    monkeypatch.setitem(globals(), "expired_keys", True)
    write_atomic(str(src), body(OLD, -500))
    c = make(src, min_check_interval=1e9)
    seen = []
    client = build_client(c, seen)
    with pytest.raises(UpstreamRenewalFailed) as err:
        c.call(lambda: invoke(client))
    no_secrets(err.value, repr(err.value), err.value.details, json.dumps(c.status(), default=str))
    assert len(seen) == 1


# ------------------------------------------------------------------------------------------------ status, hook, registry
def test_status_is_redacted_and_informative(src):
    c = make(src)
    c.current()
    status = c.status()
    text = json.dumps(status, default=str)
    no_secrets(text)
    assert status["profile"] == "default" and status["state"] == "valid" and 2900 < status["expires_in_seconds"] <= 3000
    assert status["file"]["exists"] and status["last_reload_ok_utc"] and status["last_failure"] is None and status["region"] == "us-west-2"


def test_status_flags_a_migrated_one_time_copy_that_nothing_renews(tmp_path):
    folder = tmp_path / ".orchestrator-cookie" / "config" / "migrated-files"
    folder.mkdir(parents=True)
    p = folder / "aws-credentials"
    write_atomic(str(p), body(OLD, -90000))
    os.utime(p, (time.time() - 90000, time.time() - 90000))
    status = Coordinator(str(p), "default", settle_seconds=0).status()
    assert status["state"] == "expired" and any("one-time copy" in w for w in status["warnings"]) and any("not writing here" in w for w in status["warnings"])


def test_status_for_missing_unreadable_and_provider_chain_profiles(tmp_path):
    assert Coordinator(str(tmp_path / "nope"), "default").status()["state"] == "missing"
    p = tmp_path / "c"
    p.write_text("[default]\nregion = us-west-2\n")
    assert Coordinator(str(p), "default", settle_seconds=0).status()["state"] == "provider-chain"


def test_environment_credentials_are_reported_by_name_only(src, monkeypatch):
    monkeypatch.setenv("AWS_SESSION_TOKEN", "fictional-env-token-value")
    status = make(src).status()
    assert "AWS_SESSION_TOKEN" in status["environment_credentials_present"] and "fictional-env-token-value" not in json.dumps(status)


def test_optional_refresh_command_runs_once_per_cooldown_and_only_for_expiry(src):
    write_atomic(str(src), body(OLD, -500))
    runs = []

    def runner(argv):
        runs.append(argv)
        write_atomic(str(src), body(NEW, 3000))
        return 0

    c = make(src, min_check_interval=1e9, options={"refresh_command": [os.path.abspath(os.sep + "opt" + os.sep + "refresh")], "refresh_wait": 0.0}, hook_runner=runner)
    c.current()
    with pytest.raises(Exception):
        c.call(lambda: (_ for _ in ()).throw(client_error("AccessDeniedException")))
    assert runs == []                                                           # not an expiry: the helper is never invoked
    calls = []

    def fn():
        calls.append(c.current().access_key)
        if calls[-1] == OLD[0]:
            raise expired_error()
        return "ok"

    assert c.call(fn) == "ok" and len(runs) == 1 and c.last_hook["exit_code"] == 0
    no_secrets(c.status())


def public(options):
    return {k: v for k, v in options.items() if not k.startswith("_")}


def test_options_file_accepts_only_an_absolute_argv_and_plain_text(tmp_path):
    (tmp_path / "aws-refresh.json").write_text(json.dumps({"refresh_command": ["relative/refresh"], "renewal_hint": "line\nbreak"}))
    assert public(read_options(str(tmp_path))) == {}
    absolute = os.path.abspath(os.sep + "opt" + os.sep + "refresh")
    (tmp_path / "aws-refresh.json").write_text(json.dumps({"refresh_command": [absolute, "--once"], "renewal_hint": "Run the existing refresh."}))
    assert public(read_options(str(tmp_path))) == {"refresh_command": [absolute, "--once"], "renewal_hint": "Run the existing refresh."}


def test_the_registry_shares_one_coordinator_per_source(src):
    a, b = get_coordinator(str(src), "default"), get_coordinator(str(src), "default")
    assert a is b and get_coordinator(str(src), "other") is not a


# ------------------------------------------------------------------------------------------------ bounded wait for an external refresher
def test_a_bounded_wait_picks_up_a_file_the_external_refresher_lands_late(src):
    write_atomic(str(src), body(OLD, -500))
    clock = {"t": 0.0}
    slept = []

    def fake_sleep(seconds):
        slept.append(seconds)
        clock["t"] += seconds
        if len(slept) == 3:
            write_atomic(str(src), body(NEW, 3000))                              # the refresher lands the file during the wait

    c = Coordinator(str(src), "default", min_check_interval=1e9, settle_seconds=0.0, options={"renewal_wait": 60.0}, mono=lambda: clock["t"], sleep=fake_sleep)
    c.current()
    calls = []

    def fn():
        calls.append(c.current().access_key)
        if calls[-1] == OLD[0]:
            raise expired_error()
        return "ok"

    assert c.call(fn) == "ok" and calls == [OLD[0], NEW[0]] and len(slept) == 3 and sum(slept) < 60


def test_the_wait_is_bounded_and_ends_in_the_distinct_renewal_failure(src):
    write_atomic(str(src), body(OLD, -500))
    clock = {"t": 0.0}

    def fake_sleep(seconds):
        clock["t"] += seconds

    c = Coordinator(str(src), "default", min_check_interval=1e9, settle_seconds=0.0, options={"renewal_wait": 20.0}, mono=lambda: clock["t"], sleep=fake_sleep)
    c.current()
    calls = []
    with pytest.raises(UpstreamRenewalFailed):
        c.call(lambda: calls.append(1) or (_ for _ in ()).throw(expired_error()))
    assert calls == [1] and 20 <= clock["t"] < 40


def test_no_wait_happens_unless_configured_and_never_for_other_errors(src):
    write_atomic(str(src), body(OLD, -500))
    clock = {"t": 0.0}
    c = Coordinator(str(src), "default", min_check_interval=1e9, settle_seconds=0.0, mono=lambda: clock["t"], sleep=lambda s: clock.__setitem__("t", clock["t"] + s))
    c.current()
    with pytest.raises(UpstreamRenewalFailed):
        c.call(lambda: (_ for _ in ()).throw(expired_error()))
    assert clock["t"] == 0.0



def test_an_inherited_bedrock_bearer_token_or_env_keys_never_replace_the_configured_credentials(src, monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "inherited-bearer-token-must-not-be-used-0123456789")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "FAKEINHERITED000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "inherited-secret")
    monkeypatch.setenv("AWS_PROFILE", "some-other-profile")
    c = make(src)
    seen_auth = []
    client = c.client("bedrock-runtime")

    def handler(request, **_):
        auth = request.headers.get("Authorization", b"")
        seen_auth.append(auth.decode() if isinstance(auth, bytes) else auth)
        raise RuntimeError("stop before the network")

    client.meta.events.register("before-send.bedrock-runtime.InvokeModel", handler)
    with pytest.raises(RuntimeError):
        client.invoke_model(modelId="m", body=b"{}", contentType="application/json", accept="application/json")
    assert seen_auth and seen_auth[0].startswith("AWS4-HMAC-SHA256 Credential=" + OLD[0] + "/"), seen_auth
    assert "inherited" not in seen_auth[0]
    assert any("bearer" in w.lower() for w in c.status()["warnings"])
    no_secrets(json.dumps(c.status(), default=str))


# ------------------------------------------------------------------------------------------------ review fixes (Security F2/F3/F11/F12, Reviewer S1-S4)
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode semantics")


@posix_only
def test_a_symlinked_or_group_writable_or_foreign_source_is_refused_with_a_stable_code(tmp_path):
    real = tmp_path / "real"
    write_atomic(str(real), body(OLD, 3000))
    os.utime(real, (time.time() - 5, time.time() - 5))
    link = tmp_path / "link"
    os.symlink(real, link)
    with pytest.raises(SourceError) as err:
        load_credentials(str(link), "default", settle_seconds=0)
    assert err.value.code == "unsafe_permissions"
    os.chmod(real, 0o664)
    with pytest.raises(SourceError) as err2:
        load_credentials(str(real), "default", settle_seconds=0)
    assert err2.value.code == "unsafe_permissions" and "group or others" in err2.value.message
    os.chmod(real, 0o600)
    assert load_credentials(str(real), "default", settle_seconds=0).access_key == OLD[0]
    os.chmod(tmp_path, 0o777)
    try:
        with pytest.raises(SourceError) as err3:
            load_credentials(str(real), "default", settle_seconds=0)
        assert "folder" in err3.value.message
    finally:
        os.chmod(tmp_path, 0o700)


@posix_only
def test_status_reports_unsafe_permissions_and_keeps_serving_the_last_good_set(src):
    c = make(src)
    assert c.current().access_key == OLD[0]
    os.chmod(src, 0o666)
    time.sleep(0.01)
    write_atomic(str(src), body(NEW, 3000))
    os.chmod(src, 0o666)
    assert c.current().access_key == OLD[0] and c.last_failure["code"] == "unsafe_permissions"
    assert c.status()["last_failure"]["code"] == "unsafe_permissions"


def test_duplicate_sections_or_keys_are_refused(tmp_path):
    p = tmp_path / "c"
    p.write_text(body(OLD, 3000) + "\n" + body(NEW, 3000))
    with pytest.raises(SourceError) as err:
        load_credentials(str(p), "default", settle_seconds=0)
    assert err.value.code == "incomplete" and "duplicate" in err.value.message


def test_temporary_keys_without_a_token_are_rejected_even_on_the_very_first_load(tmp_path):
    p = tmp_path / "c"
    p.write_text("[default]\naws_access_key_id = ASIAFICTIONAL00001\naws_secret_access_key = fictional-secret-0123456789abcdef\n")
    os.utime(p, (time.time() - 5, time.time() - 5))
    with pytest.raises(SourceError) as err:
        load_credentials(str(p), "default", settle_seconds=0)
    assert err.value.code == "incomplete"


def test_a_file_that_legitimately_drops_its_token_is_accepted_once_it_has_been_stable(src):
    c = make(src)
    c.current()
    write_atomic(str(src), "[default]\naws_access_key_id = FAKELONGLIVED0001\naws_secret_access_key = fictional-long-lived-secret-0123456789\n")
    assert c.current().access_key == OLD[0]                              # fresh: could be a partial write
    old = time.time() - 120
    os.utime(src, (old, old))
    c._last_check = -1e9
    assert c.current().access_key == "FAKELONGLIVED0001"                 # stable for >30 s: a real change, not a stuck state


def test_the_renewal_wait_does_not_block_other_threads_that_sign_with_the_last_good_credentials(src):
    write_atomic(str(src), body(OLD, 3000))
    c = Coordinator(str(src), "default", min_check_interval=0.0, settle_seconds=0.0, options={"renewal_wait": 3.0})   # 0.0: every current() takes the main lock
    c.current()
    started, finished = threading.Event(), []

    def slow_expired():
        started.set()
        try:
            c.call(lambda: (_ for _ in ()).throw(expired_error()))
        except UpstreamRenewalFailed:
            finished.append(time.monotonic())

    t = threading.Thread(target=slow_expired)
    t0 = time.monotonic()
    t.start()
    started.wait(2)
    time.sleep(0.4)
    t1 = time.monotonic()
    assert c.current().access_key == OLD[0]                              # served immediately while the other thread waits for a renewal
    assert time.monotonic() - t1 < 0.5
    t.join(10)
    assert finished and finished[0] - t0 >= 2.5


def test_a_coalesced_reload_does_not_claim_usable_credentials_when_the_new_set_is_expired(src):
    c = make(src, min_check_interval=1e9)
    c.current()
    gen = c.generation
    write_atomic(str(src), body(NEW, -300))
    c._last_check = -1e9
    c.current()
    outcome = c.reload("expired-token", saw_generation=gen)
    assert outcome.coalesced and outcome.usable is False


@posix_only
def test_refresh_command_is_ignored_unless_the_options_file_is_trusted(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir(mode=0o700)
    f = cfg / "aws-refresh.json"
    f.write_text(json.dumps({"refresh_command": [os.path.abspath(os.sep + "opt" + os.sep + "refresh")]}))
    os.chmod(f, 0o600)
    assert "refresh_command" in read_options(str(cfg))
    os.chmod(f, 0o666)
    out = read_options(str(cfg))
    assert "refresh_command" not in out and "writable by group or others" in out["options_warning"]
    os.chmod(f, 0o600)
    os.chmod(cfg, 0o777)
    try:
        assert "refresh_command" not in read_options(str(cfg))
    finally:
        os.chmod(cfg, 0o700)
    os.chmod(cfg, 0o700)
    f.unlink()
    (cfg / "real.json").write_text("{}")
    os.symlink(cfg / "real.json", f)
    assert "refresh_command" not in read_options(str(cfg))


@posix_only
def test_the_hook_refuses_an_untrusted_executable(tmp_path, src):
    prog = tmp_path / "helper"
    prog.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(prog, 0o777)                                                 # world-writable program
    write_atomic(str(src), body(OLD, -500))
    c = make(src, min_check_interval=1e9, options={"refresh_command": [str(prog)], "refresh_wait": 0.0})
    c.current()
    with pytest.raises(UpstreamRenewalFailed):
        c.call(lambda: (_ for _ in ()).throw(expired_error()))
    assert c.last_hook["error"] == "untrusted_executable"
    assert c.status()["refresh_command_program"] == "helper"


# ------------------------------------------------------------------------------------------------ b4r3: the status view follows a rotation
def test_status_follows_a_rotation_without_a_signing_call_and_without_a_restart(src):
    c = make(src)
    c.current()
    first = c.status()
    assert first["generation"] == 1 and 2900 < first["expires_in_seconds"] <= 3000
    time.sleep(0.01)
    write_atomic(str(src), body(NEW, 7000))                       # the external refresher rotates the file; nobody signs anything
    seen = c.status()
    assert seen["state"] == "valid" and seen["generation"] == 2 and seen["expires_in_seconds"] > 6900
    assert seen["last_reload_trigger"] == "status-check" and seen["last_failure"] is None
    reloads = c.reload_count
    assert c.current().access_key == NEW[0] and c.reload_count == reloads        # the next signing call uses it without another read
    no_secrets(json.dumps(seen, default=str))


def test_status_does_not_reread_a_file_that_did_not_change(src, monkeypatch):
    c = make(src)
    c.current()
    calls = []
    real = coord_module.load_credentials
    monkeypatch.setattr(coord_module, "load_credentials", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    for _ in range(5):
        c.status()
    assert calls == []


def test_status_keeps_the_previous_set_for_a_half_written_file_and_bounds_its_re_reads(src, monkeypatch):
    c = make(src)
    c.current()
    time.sleep(0.01)
    write_atomic(str(src), "[default]\naws_access_key_id = " + NEW[0] + "\n")           # incomplete: no secret, no token
    calls = []
    real = coord_module.load_credentials
    monkeypatch.setattr(coord_module, "load_credentials", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    last = None
    for _ in range(6):
        last = c.status()
    assert last["state"] == "valid" and last["generation"] == 1 and 2900 < last["expires_in_seconds"] <= 3000
    assert last["last_failure"]["code"] in ("incomplete", "unstable")
    assert len(calls) == 1                                          # one probe inside the interval, not one per poll
    assert c.current().access_key == OLD[0]                         # signing keeps the previous good credentials
    no_secrets(json.dumps(last, default=str))
