"""Coordinator: single-flight reloads, error classification, one bounded retry, redacted status, boto3 integration.

Nothing in this module prints, logs, returns or raises a credential value.  Exceptions it raises carry only stable codes and safe text.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .source import Loaded, SourceError, credential_state, load_credentials, stat_signature

EXPIRED_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired", "TokenRefreshRequired"})
INVALID_CODES = frozenset({"UnrecognizedClientException", "InvalidClientTokenId", "InvalidSignatureException", "SignatureDoesNotMatch",
                           "IncompleteSignature", "InvalidAccessKeyId"})
DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException", "UnauthorizedException", "AuthorizationError", "UnauthorizedOperation"})
MODEL_CODES = frozenset({"ResourceNotFoundException", "ModelNotReadyException", "ModelErrorException", "ModelNotFound"})
THROTTLE_CODES = frozenset({"ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException", "Throttling"})
NETWORK_CLASSES = frozenset({"ConnectTimeoutError", "ReadTimeoutError", "EndpointConnectionError", "ConnectionClosedError", "HTTPClientError",
                             "ProxyConnectionError", "SSLError", "ConnectionError", "TimeoutError", "ClientConnectionError"})
NO_CREDENTIAL_CLASSES = frozenset({"NoCredentialsError", "PartialCredentialsError", "ProfileNotFound", "CredentialRetrievalError"})

CATEGORY_TEXT = {
    "expired_token": "AWS credentials are expired.",
    "invalid_credentials": "AWS rejected the credentials as invalid (not merely expired).",
    "access_denied": "AWS denied access for the configured credentials, profile or model.",
    "model_config": "The configured Bedrock model or inference profile is unavailable in this region.",
    "model_request": "Bedrock rejected the request for the configured model or profile.",
    "throttled": "Bedrock throttled the request.",
    "network": "The Bedrock endpoint could not be reached or timed out.",
    "no_credentials": "No usable AWS credentials are available from the configured source.",
    "source_error": "The configured AWS credential file cannot be used.",
    "upstream_renewal_failed": "AWS credentials are expired and the configured source has not been renewed.",
    "unknown": "An unexpected client failure occurred.",
}


class AwsRefreshError(RuntimeError):
    """Base: ``category`` is stable; ``safe_reason`` is operator-visible text with no secrets."""

    category = "unknown"

    def __init__(self, safe_reason: str, *, category: str | None = None, details: dict | None = None) -> None:
        super().__init__(safe_reason)
        self.safe_reason = safe_reason
        if category:
            self.category = category
        self.details = details or {}


class UpstreamRenewalFailed(AwsRefreshError):
    category = "upstream_renewal_failed"


class CredentialsStillExpired(AwsRefreshError):
    category = "expired_token"


class CredentialSourceError(AwsRefreshError):
    category = "source_error"


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if isinstance(code, str):
            return code
    return ""


def classify_error(exc: BaseException) -> str:
    """Stable category for an exception.  ONLY definite expiry codes map to ``expired_token`` (never a bare 403, timeout or schema error)."""
    if isinstance(exc, AwsRefreshError):
        return exc.category
    code, name = _error_code(exc), exc.__class__.__name__
    text = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        text = str(response.get("Error", {}).get("Message", "")).lower()
    if code in EXPIRED_CODES or name in EXPIRED_CODES or "security token included in the request is expired" in text:
        return "expired_token"
    if code in INVALID_CODES or "security token included in the request is invalid" in text:
        return "invalid_credentials"
    if code in DENIED_CODES or name in ("AccessDeniedException",):
        return "access_denied"
    if code in MODEL_CODES:
        return "model_config"
    if code == "ValidationException":
        return "model_request"
    if code in THROTTLE_CODES:
        return "throttled"
    if name in NO_CREDENTIAL_CLASSES:
        return "no_credentials"
    if name in NETWORK_CLASSES or isinstance(exc, (TimeoutError, ConnectionError)):
        return "network"
    return "unknown"


def describe_category(category: str) -> str:
    return CATEGORY_TEXT.get(category, CATEGORY_TEXT["unknown"])


@dataclass(frozen=True)
class ReloadOutcome:
    changed: bool                 # a different credential set is now in use
    usable: bool                  # ... and it is not expired
    state: str
    reason: str                   # reloaded | unchanged | coalesced | source_error:<code> | refresh_command
    coalesced: bool = False


@dataclass
class _Attempt:
    generation: int
    at: float
    outcome: ReloadOutcome


def _options_untrusted(path: str, config_dir: str) -> str:
    """Why aws-refresh.json may not name a command ('' = trusted).  POSIX only: a regular file, owned by this user, nobody else can write it or its folder."""
    if os.name != "posix" or not hasattr(os, "getuid"):
        return ""
    import stat as _stat
    try:
        lst = os.lstat(path)
        parent = os.lstat(config_dir)
    except OSError:
        return ""
    if _stat.S_ISLNK(lst.st_mode) or not _stat.S_ISREG(lst.st_mode):
        return "it is not a regular file"
    if lst.st_uid != os.getuid():
        return "it is owned by another user"
    if lst.st_mode & 0o022:
        return "it is writable by group or others"
    if parent.st_mode & 0o022 and not parent.st_mode & _stat.S_ISVTX:
        return "its folder is writable by group or others"
    return ""


def _executable_is_trusted(argv0: str) -> bool:
    if os.name != "posix" or not hasattr(os, "getuid"):
        return os.path.isfile(argv0)
    try:
        st = os.stat(argv0)
    except OSError:
        return False
    import stat as _stat
    return _stat.S_ISREG(st.st_mode) and st.st_uid in (os.getuid(), 0) and not st.st_mode & 0o022 and bool(st.st_mode & 0o111)


def read_options(config_dir: str | None) -> dict:
    """Optional ``<config_dir>/aws-refresh.json``: {"refresh_command": [absolute argv...], "renewal_hint": str}.  Invalid content is ignored."""
    out: dict = {}
    if not config_dir:
        return out
    path = os.path.join(config_dir, "aws-refresh.json")
    try:
        trust_problem = _options_untrusted(path, config_dir)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    out["_config_dir"] = config_dir
    if not isinstance(data, dict):
        return out
    cmd = data.get("refresh_command")
    if cmd is not None and trust_problem:
        out["options_warning"] = "aws-refresh.json is ignored for its command: " + trust_problem
        cmd = None
    if isinstance(cmd, list) and 1 <= len(cmd) <= 16 and all(isinstance(x, str) and x and "\0" not in x and len(x) < 512 for x in cmd) and os.path.isabs(cmd[0]):
        out["refresh_command"] = list(cmd)
    wait = data.get("renewal_wait")
    if isinstance(wait, (int, float)) and not isinstance(wait, bool) and 0 < wait <= 300:
        out["renewal_wait"] = float(wait)
    hint = data.get("renewal_hint")
    if isinstance(hint, str) and 0 < len(hint) <= 400 and "\n" not in hint:
        out["renewal_hint"] = hint
    return out


_ENV_NAMES = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_BEARER_TOKEN_BEDROCK",
              "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE")


class Coordinator:
    def __init__(self, path: str, profile: str, *, region: str | None = None, config_file: str | None = None, options: dict | None = None,
                 clock: Callable[[], datetime] | None = None, mono: Callable[[], float] | None = None,
                 sleep: Callable[[float], None] | None = None, min_check_interval: float = 0.5, near_expiry_seconds: float = 90.0,
                 failure_cooldown: float = 5.0, settle_seconds: float = 0.2, hook_runner: Callable[..., int] | None = None) -> None:
        self.path, self.profile, self.region, self.config_file = path, profile or "default", region, config_file
        self.options = options or {}
        self._custom_clock = clock is not None
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._mono = mono or time.monotonic
        self._sleep = sleep or time.sleep
        self._min_interval = min_check_interval
        self._near = near_expiry_seconds
        self._cooldown = failure_cooldown
        self._settle = settle_seconds
        self._hook_runner = hook_runner
        self._reload_lock = threading.RLock()
        self._renew_lock = threading.Lock()                 # single-flight for the (slow) refresh hook + renewal wait, so the main lock is never held while sleeping
        self._state_lock = threading.Lock()
        self._loaded: Loaded | None = None
        self._last_check = -1e9
        self._status_probe_at = -1e9
        self.generation = 0
        self.reload_count = 0
        self.change_count = 0
        self.last_ok_utc: datetime | None = None
        self.last_trigger = ""
        self.last_failure: dict | None = None
        self._attempt: _Attempt | None = None
        self._hook_last = -1e9
        self.last_hook: dict | None = None
        self._kind = "file"

    # ---------------------------------------------------------------- reading
    def kind(self) -> str:
        return self._kind

    def _record_failure(self, code: str, message: str) -> None:
        with self._state_lock:
            self.last_failure = {"code": code, "message": message[:240], "at": self._clock().isoformat()}

    def _load(self, trigger: str) -> tuple[Loaded | None, ReloadOutcome]:
        old = self._loaded
        try:
            new = load_credentials(self.path, self.profile, now=self._clock() if self._custom_clock else None,
                                   settle_seconds=self._settle, sleep=self._sleep,
                                   previous_had_token=bool(old and old.token), previous_had_expiry=bool(old and old.expiry))
        except SourceError as exc:
            if exc.code == "no_static_keys":
                self._kind = "chain"
                self._record_failure(exc.code, exc.message)
                return None, ReloadOutcome(False, True, "unknown", "chain")
            self._record_failure(exc.code, exc.message)
            kept_ok = old is not None and credential_state(old.expiry, self._clock(), self._near) != "expired"
            return None, ReloadOutcome(False, kept_ok, credential_state(old.expiry, self._clock(), self._near) if old else "unknown",
                                       f"source_error:{exc.code}")
        self._kind = "file"
        with self._state_lock:
            changed = old is None or new.identity != old.identity
            if changed:
                self.generation += 1
                self.change_count += 1
            self._loaded = new
            self._last_check = self._mono()
            self.reload_count += 1
            self.last_ok_utc = self._clock()
            self.last_trigger = trigger
            self.last_failure = None
        state = credential_state(new.expiry, self._clock(), self._near)
        return new, ReloadOutcome(changed, state != "expired", state, "reloaded" if changed else "unchanged")

    def current(self) -> Loaded:
        """Hot path used for every signing call: a stat and, only if the file changed, a validated re-read."""
        loaded = self._loaded
        if loaded is not None and self._mono() - self._last_check < self._min_interval:
            return loaded
        with self._reload_lock:
            loaded = self._loaded
            try:
                sig = stat_signature(self.path)
            except SourceError as exc:
                self._record_failure(exc.code, exc.message)
                if loaded is not None and credential_state(loaded.expiry, self._clock(), self._near) != "expired":
                    self._last_check = self._mono()
                    return loaded
                raise CredentialSourceError(exc.message, details={"code": exc.code}) from None
            if loaded is not None and sig == loaded.signature:
                self._last_check = self._mono()
                return loaded
            new, outcome = self._load("signing")
            if new is None:
                if self._kind == "chain":
                    raise CredentialSourceError("The profile holds no access keys; use the botocore provider chain.", details={"code": "chain"})
                if self._loaded is not None and outcome.usable:
                    self._last_check = self._mono()
                    return self._loaded            # keep the previous GOOD credentials; the bad candidate is never used
                code = outcome.reason.split(":", 1)[-1]
                raise CredentialSourceError("The AWS credential file cannot be used right now (" + code + ").", details={"code": code})
            return new

    # ---------------------------------------------------------------- reload / retry
    def reload(self, trigger: str = "manual", *, saw_generation: int | None = None) -> ReloadOutcome:
        """Single-flight re-read.  ``saw_generation`` = the credential generation the failed request used."""
        if trigger != "expired-token":
            with self._reload_lock:
                new, outcome = self._load(trigger)
                if saw_generation is not None:
                    self._attempt = _Attempt(saw_generation, self._mono(), outcome)
                return outcome
        with self._renew_lock:                                  # concurrent expiry failures queue here, then coalesce onto the first one's result
            coalesced = self._coalesced(saw_generation)
            if coalesced is not None:
                return coalesced
            self._run_refresh_command()                        # slow: runs WITHOUT the main lock, so signing threads keep working with the last good set
            with self._reload_lock:
                new, outcome = self._load(trigger)
            if not (outcome.changed and outcome.usable):
                outcome = self._wait_for_renewal(outcome)
            with self._reload_lock:
                if saw_generation is not None:
                    self._attempt = _Attempt(saw_generation, self._mono(), outcome)
            return outcome

    def _coalesced(self, saw_generation: int | None):
        if saw_generation is None:
            return None
        with self._reload_lock:
            if self.generation != saw_generation:
                state = self.state()
                return ReloadOutcome(True, state != "expired", state, "coalesced", coalesced=True)
            att = self._attempt
            if att is not None and att.generation == saw_generation and self._mono() - att.at < self._cooldown:
                return ReloadOutcome(att.outcome.changed, att.outcome.usable, att.outcome.state, "coalesced", coalesced=True)
        return None

    def _wait_for_renewal(self, outcome: ReloadOutcome) -> ReloadOutcome:
        """Bounded wait for the EXTERNAL refresher to land a newer file (some write just after expiry).  Off unless ``renewal_wait`` > 0.  The sleep happens
        outside the main lock; only each re-read takes it."""
        wait = min(float(self.options.get("renewal_wait", 0) or 0), 300.0)
        if wait <= 0 or outcome.reason == "chain":
            return outcome
        deadline = self._mono() + wait
        while self._mono() < deadline:
            self._sleep(min(5.0, max(0.05, deadline - self._mono())))
            with self._reload_lock:
                new, latest = self._load("expired-token")
            if latest.changed and latest.usable:
                return latest
            outcome = latest if new is not None or latest.reason != "unchanged" else outcome
        return outcome

    def _run_refresh_command(self) -> None:
        argv = self.options.get("refresh_command")
        if not argv or self._mono() - self._hook_last < float(self.options.get("refresh_cooldown", 120)):
            return
        if self._hook_runner is None and not _executable_is_trusted(argv[0]):
            self.last_hook = {"at": self._clock().isoformat(), "error": "untrusted_executable"}
            return
        self._hook_last = self._mono()
        before = None
        try:
            before = stat_signature(self.path)
        except SourceError:
            pass
        started = self._clock().isoformat()
        try:
            if self._hook_runner is not None:
                rc = self._hook_runner(list(argv))
            else:
                import subprocess
                env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USERPROFILE", "SYSTEMROOT") if k in os.environ}
                cwd = self.options.get("_config_dir") or None
                rc = subprocess.run(list(argv), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                                    cwd=cwd if cwd and os.path.isdir(cwd) else None, timeout=float(self.options.get("refresh_timeout", 30)), check=False).returncode
            self.last_hook = {"at": started, "exit_code": int(rc)}
        except Exception as exc:
            self.last_hook = {"at": started, "error": exc.__class__.__name__}
            return
        end = self._mono() + float(self.options.get("refresh_wait", 10))
        while self._mono() < end:
            try:
                if stat_signature(self.path) != before:
                    break
            except SourceError:
                pass
            self._sleep(0.5)

    def call(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn``.  On a CONFIRMED expired-token rejection: one coordinated reload, then ONE retry; nothing else is ever retried."""
        used = self.generation
        try:
            return fn()
        except Exception as exc:
            if classify_error(exc) != "expired_token":
                raise
        outcome = self.reload("expired-token", saw_generation=used)
        if outcome.reason != "chain" and (not outcome.usable or not (outcome.changed or outcome.coalesced)):
            raise UpstreamRenewalFailed(self.renewal_message(), details=self.status_brief()) from None
        try:
            return fn()
        except Exception as exc2:
            if classify_error(exc2) == "expired_token":
                raise CredentialsStillExpired("AWS rejected the reloaded credentials as expired as well. " + self.renewal_hint(),
                                              details=self.status_brief()) from None
            raise

    # ---------------------------------------------------------------- status
    def state(self) -> str:
        loaded = self._loaded
        return credential_state(loaded.expiry, self._clock(), self._near) if loaded else "unknown"

    def renewal_hint(self) -> str:
        return self.options.get("renewal_hint") or ("Renew the upstream login with your existing AWS refresh procedure, then use Reload credentials. "
                                                    "This application cannot renew a human login.")

    def renewal_message(self) -> str:
        info = self._file_info()
        age = info.get("age_seconds")
        parts = ["AWS credentials are expired and the configured credential file has not been renewed"]
        if age is not None:
            parts.append(f" (last written {_human(age)} ago")
            parts.append(")" if not info.get("path_hint") else "; " + info["path_hint"] + ")")
        return "".join(parts) + ". " + self.renewal_hint()

    def _file_info(self) -> dict:
        info: dict = {"path": self.path, "exists": False}
        try:
            st = os.stat(self.path)
        except OSError:
            return info
        info.update({"exists": True, "mode": oct(st.st_mode & 0o777), "size": st.st_size,
                     "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                     "age_seconds": max(0, int(self._clock().timestamp() - st.st_mtime)), "is_symlink": os.path.islink(self.path)})
        if _looks_like_migrated_copy(self.path):
            info["path_hint"] = "this is a one-time migration copy that nothing renews"
        return info

    _STATUS_PROBE_INTERVAL = 2.0

    def _follow_rotation_for_status(self, loaded: Loaded) -> Loaded:
        """The status view must describe the credentials the NEXT signing call will use.  When the file changed since the last load (the external
        refresher rotated it) take the same validated path a signing call takes; a bad candidate keeps the previous good set and is reported.
        Throttled, so a polling page cannot cause a re-read storm while a file stays unusable."""
        try:
            sig = stat_signature(self.path)
        except SourceError:
            return loaded
        if sig == loaded.signature:
            return loaded
        now = self._mono()
        if now - self._status_probe_at < self._STATUS_PROBE_INTERVAL:
            return loaded
        self._status_probe_at = now
        try:
            with self._reload_lock:
                latest = self._loaded or loaded                 # another thread may have adopted the new file meanwhile
                if latest.signature == sig:
                    return latest
                probe, _ = self._load("status-check")
                return probe or self._loaded or loaded
        except Exception:                                       # noqa: BLE001 - the status view must never fail because of a probe
            return self._loaded or loaded

    def status_brief(self) -> dict:
        return {"state": self.state(), "path": self.path, "profile": self.profile}

    def status(self) -> dict:
        now = self._clock()
        loaded = self._loaded
        file_info = self._file_info()
        sig_state = None
        if loaded is None and file_info.get("exists"):
            try:                                                   # read-only probe so the status view is useful before first use
                with self._reload_lock:
                    probe, _ = self._load("status")
                loaded = probe
            except Exception:
                loaded = self._loaded
        if loaded is not None and file_info.get("exists"):
            loaded = self._follow_rotation_for_status(loaded)
        state = credential_state(loaded.expiry, now, self._near) if loaded else ("missing" if not file_info.get("exists") else "unreadable")
        if loaded is not None and loaded.expiry is None:
            state = "unknown"
        if loaded is None and self.last_failure:
            state = {"profile_missing": "profile-missing", "incomplete": "incomplete", "unstable": "incomplete", "no_static_keys": "provider-chain", "unsafe_permissions": "unsafe-permissions"}.get(self.last_failure["code"], state)
        warnings: list[str] = []
        if _looks_like_migrated_copy(self.path):
            warnings.append("The configured file is a one-time copy made during migration. Nothing renews it. Point the application at the file your refresh mechanism writes.")
        if state == "expired" and file_info.get("age_seconds") is not None and file_info["age_seconds"] > 3600:
            warnings.append(f"The file was last written {_human(file_info['age_seconds'])} ago and its credentials are expired: the refresh mechanism is not writing here.")
        if self.options.get("options_warning"):
            warnings.append(self.options["options_warning"])
        env_present = {name: (name in os.environ) for name in _ENV_NAMES if name in os.environ}
        if any(n in env_present for n in ("AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "AWS_BEARER_TOKEN_BEDROCK")):
            warnings.append("Environment credentials (or a Bedrock bearer token) are present in this process; they are ignored because an explicit profile and file are configured.")
        return {
            "provider": "shared credentials file, re-read on change" if self._kind == "file" else "botocore provider chain (profile has no access keys)",
            "source_path": self.path, "config_file": self.config_file, "profile": self.profile, "region": self.region or "unknown",
            "file": file_info, "state": state,
            "expires_at_utc": loaded.expiry.isoformat() if loaded and loaded.expiry else None,
            "expires_in_seconds": int((loaded.expiry - now).total_seconds()) if loaded and loaded.expiry else None,
            "last_reload_ok_utc": self.last_ok_utc.isoformat() if self.last_ok_utc else None, "last_reload_trigger": self.last_trigger or None,
            "last_failure": self.last_failure, "generation": self.generation, "reload_count": self.reload_count, "credential_changes": self.change_count,
            "refresh_command_configured": bool(self.options.get("refresh_command")), "last_refresh_command": self.last_hook,
            "refresh_command_program": os.path.basename((self.options.get("refresh_command") or [""])[0]) or None,
            "environment_credentials_present": sorted(env_present), "warnings": warnings,
            "renewal_hint": self.renewal_hint(),
        }

    # ---------------------------------------------------------------- boto3
    def boto_session(self):
        """A boto3 Session whose credentials are re-validated on every signing call (no cached snapshot)."""
        import boto3
        import botocore.session
        from botocore.credentials import CredentialProvider

        bsession = botocore.session.get_session()
        bsession.set_config_variable("profile", self.profile)          # an explicit profile also removes botocore's environment provider
        bsession.set_config_variable("credentials_file", self.path)
        if self.config_file:
            bsession.set_config_variable("config_file", self.config_file)
        if self.region:
            bsession.set_config_variable("region", self.region)
        if self._kind != "chain":
            try:
                self.current()                                             # fail early (and detect 'chain') before a client exists
            except CredentialSourceError as exc:
                missing_but_configured = exc.details.get("code") == "missing" and bool(self.config_file) and os.path.isfile(self.config_file)
                if missing_but_configured:
                    self._kind = "chain"                                   # e.g. credential_process / role in the config file only
                elif self._kind != "chain":
                    raise
        if self._kind == "file":
            credentials = _credentials_class()(self)
            coordinator = self

            class _Provider(CredentialProvider):
                METHOD = "nrdp-aws-refresh"
                CANONICAL_NAME = "nrdp-aws-refresh"

                def load(self):                                                # noqa: D401
                    return credentials

            bsession.get_component("credential_provider").providers.insert(0, _Provider())
        return boto3.Session(botocore_session=bsession, region_name=self.region)

    def client(self, service: str = "bedrock-runtime", **kwargs):
        """A client for *service*.  SigV4 is forced when the file supplies static keys, so an inherited ``AWS_BEARER_TOKEN_BEDROCK`` can never
        silently replace the configured, refreshed credentials."""
        if self._kind == "file" or (self._kind != "chain" and os.path.isfile(self.path)):
            from botocore.config import Config
            forced = Config(signature_version="v4")
            user = kwargs.pop("config", None)
            kwargs["config"] = forced.merge(user) if user is not None else forced
        return self.boto_session().client(service, region_name=self.region, **kwargs)


_cls: Any = None


def _credentials_class():
    global _cls
    if _cls is not None:
        return _cls
    from botocore.credentials import Credentials, ReadOnlyCredentials

    class FileCredentials(Credentials):
        method = "nrdp-aws-refresh"

        def __init__(self, coordinator: Coordinator) -> None:       # noqa: D401 - deliberately not calling the base __init__
            self._coordinator = coordinator

        @property
        def access_key(self):
            return self._coordinator.current().access_key

        @access_key.setter
        def access_key(self, _value):
            pass

        @property
        def secret_key(self):
            return self._coordinator.current().secret_key

        @secret_key.setter
        def secret_key(self, _value):
            pass

        @property
        def token(self):
            return self._coordinator.current().token

        @token.setter
        def token(self, _value):
            pass

        def get_frozen_credentials(self):
            loaded = self._coordinator.current()
            return ReadOnlyCredentials(loaded.access_key, loaded.secret_key, loaded.token)

    _cls = FileCredentials
    return _cls


def _looks_like_migrated_copy(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    return "/migrated-files/" in p or "/.orchestrator-cookie/config/aws-" in p


def _human(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} days"


_REGISTRY: dict[tuple[str, str], Coordinator] = {}
_REGISTRY_LOCK = threading.Lock()


def get_coordinator(path: str, profile: str | None, *, region: str | None = None, config_file: str | None = None, options: dict | None = None) -> Coordinator:
    key = (os.path.abspath(path), profile or "default")
    with _REGISTRY_LOCK:
        existing = _REGISTRY.get(key)
        if existing is None:
            existing = _REGISTRY[key] = Coordinator(key[0], key[1], region=region, config_file=config_file, options=options)
        else:
            if region:
                existing.region = region
            if config_file:
                existing.config_file = config_file
            if options is not None:
                existing.options = options
        return existing


def reset_registry() -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


_LAST_MODEL_ERROR: dict | None = None
_LAST_LOCK = threading.Lock()


def note_model_error(category: str) -> None:
    """Remember the CATEGORY (never the message body) of the latest model-call failure for the AWS status view."""
    global _LAST_MODEL_ERROR
    with _LAST_LOCK:
        _LAST_MODEL_ERROR = {"category": category, "label": describe_category(category), "at": datetime.now(timezone.utc).isoformat()}


def last_model_error() -> dict | None:
    with _LAST_LOCK:
        return dict(_LAST_MODEL_ERROR) if _LAST_MODEL_ERROR else None


def clear_model_error() -> None:
    global _LAST_MODEL_ERROR
    with _LAST_LOCK:
        _LAST_MODEL_ERROR = None
