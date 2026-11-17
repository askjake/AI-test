"""Refresh-aware AWS credential use shared by the dashboard, the runner and the native Windows backend.

Neutral package: imports nothing from ``dashboard``, ``orchestrator`` or ``orchestrator_cookie``; botocore is imported lazily.

Design (see docs/AWS_REFRESH.md):
* ONE authoritative source file per process (the configured shared-credentials file).  The source is re-validated on every signing
  call by a cheap ``stat`` signature (device, inode, mtime, size), so an atomic ``rename`` over the file is noticed immediately, no restart.
* A candidate file is accepted only if it is stable (identical signature before/after the read and settled), parses, and holds a complete
  profile; otherwise the previous good credentials stay in use and the failure is recorded.  A partially written file is never used.
* Reloads are single-flight: concurrent failures cause one re-read.  A confirmed expired-token rejection triggers at most ONE reload and ONE retry
  of the failed request; nothing else is ever replayed.
* Status/diagnostics carry paths, profile, provider kind, timestamps, states and error codes only - never key, secret or token values.
"""
from .source import (EXPIRY_KEYS, Loaded, Signature, SourceError, credential_state, load_credentials, parse_expiry, stat_signature)  # noqa: F401
from .coordinator import (AwsRefreshError, Coordinator, CredentialsStillExpired, ReloadOutcome, UpstreamRenewalFailed, classify_error,  # noqa: F401
                          describe_category, get_coordinator, last_model_error, note_model_error, clear_model_error, read_options, reset_registry)
