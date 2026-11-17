"""Action guardrails: keep the agent inside the target window (Phase 8).

The agent drives the focused target window by vision. These guardrails refuse actions
that would escape that window or destabilise the session before they reach ``computer.py``:

- **Window-switching / launcher chords** (``alt+Tab``, ``super``, ``alt+F2``) — would move
  focus off the window under test.
- **App-exit chords** (``alt+F4``, ``ctrl+q``, ``ctrl+w``) — would close the target the
  test is meant to drive.
- **System / display chords** (``ctrl+alt+Delete``, ``ctrl+alt+BackSpace``,
  ``ctrl+alt+F<n>`` VT switches) — would affect the container/display, not the app.

A blocked action is *not* executed; the loop tells the model it was refused and why, so the
model can choose a different action. This is the action-guardrail half of P8-6; the
system-prompt half (instructing the model to stay in-window) lives in ``agent.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Individual keys that must never be sent alone (they leave the window / hit the system).
_BLOCKED_BARE_KEYS = frozenset({"super", "super_l", "super_r", "meta", "hyper"})

# Modifier names, used to normalise a chord into (sorted modifiers, base key).
_MODIFIERS = frozenset({"ctrl", "control", "alt", "shift", "super", "meta", "cmd", "win"})

_MODIFIER_ALIASES = {"control": "ctrl", "cmd": "super", "win": "super", "meta": "super"}


def _normalise_chord(combo: str) -> tuple[frozenset[str], str]:
    """Split ``"ctrl+Alt+F1"`` into (frozenset{'ctrl','alt'}, 'f1'); base key lower-cased."""
    parts = [p.strip().lower() for p in combo.split("+") if p.strip()]
    mods: set[str] = set()
    base = ""
    for p in parts:
        canonical = _MODIFIER_ALIASES.get(p, p)
        if canonical in _MODIFIERS:
            mods.add(canonical)
        else:
            base = p
    return frozenset(mods), base


# Default blocked chords as (modifiers, base-key) pairs. Comparing on the normalised form
# makes order/case/alias differences ("Alt+F4" vs "alt+f4") irrelevant.
def _chord(*keys: str) -> tuple[frozenset[str], str]:
    return _normalise_chord("+".join(keys))


_DEFAULT_BLOCKED_CHORDS = frozenset(
    {
        _chord("alt", "F4"),      # close window
        _chord("ctrl", "q"),      # quit app
        _chord("ctrl", "w"),      # close tab/window
        _chord("alt", "Tab"),     # switch window
        _chord("alt", "shift", "Tab"),
        _chord("alt", "F2"),      # run dialog / launcher
        _chord("ctrl", "alt", "Delete"),
        _chord("ctrl", "alt", "BackSpace"),  # kills the X server on many setups
    }
)


class GuardrailViolation(Exception):
    """Raised by :meth:`Guardrails.enforce` when an action is refused."""


@dataclass
class Guardrails:
    """Decides whether a computer action may run.

    ``blocked_chords`` are normalised ``(modifiers, base)`` pairs; ``blocked_bare_keys`` are
    single keys refused on their own. Both default to a conservative built-in set and can be
    extended per project. ``block_ctrl_alt_function_keys`` refuses every ``ctrl+alt+F<n>``
    (Linux virtual-terminal switches), which can't all be enumerated up front.
    """

    blocked_chords: frozenset[tuple[frozenset[str], str]] = field(
        default_factory=lambda: _DEFAULT_BLOCKED_CHORDS
    )
    blocked_bare_keys: frozenset[str] = field(default_factory=lambda: _BLOCKED_BARE_KEYS)
    block_ctrl_alt_function_keys: bool = True

    def check(self, action: str | None, inp: dict) -> str | None:
        """Return a refusal reason if ``action`` is disallowed, else ``None``.

        Only ``key`` actions are gated; mouse/type/screenshot actions are always allowed
        because they act within the focused window by construction.
        """
        if action != "key":
            return None
        combo = (inp.get("text") or "").strip()
        if not combo:
            return None

        mods, base = _normalise_chord(combo)

        # A lone key with no real base (e.g. "super" alone) normalises to a single modifier
        # and an empty base; treat that bare press as a blocked key.
        bare = base or (next(iter(mods)) if len(mods) == 1 else "")
        if not base and bare in self.blocked_bare_keys:
            return f"key {combo!r} would leave the target window and is blocked"
        if not mods and base in self.blocked_bare_keys:
            return f"key {combo!r} would leave the target window and is blocked"

        if (mods, base) in self.blocked_chords:
            return f"key combo {combo!r} (window/app/system control) is blocked"

        if (
            self.block_ctrl_alt_function_keys
            and mods == frozenset({"ctrl", "alt"})
            and len(base) >= 2
            and base[0] == "f"
            and base[1:].isdigit()
        ):
            return f"key combo {combo!r} (virtual-terminal switch) is blocked"

        return None

    def enforce(self, action: str | None, inp: dict) -> None:
        """Raise :class:`GuardrailViolation` if the action is disallowed."""
        reason = self.check(action, inp)
        if reason is not None:
            raise GuardrailViolation(reason)


# Module-level default used by the agent loop when no project override is supplied.
DEFAULT_GUARDRAILS = Guardrails()
