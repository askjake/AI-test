"""Stateful desktop simulator + harness for browser_verify tests (b4r12-dev).

DesktopSim models ONLY what the real adapter contract gives the controller: screenshot() -> PNG, key(combo), type(text).  It has no window
inventory.  OraclePageClassifier stands in for the (unimplemented, unqualified) page-classification model: it reads the simulator's truth
about the TOP Chrome window only, exactly like a model reading pixels (it cannot tell whose window it is).  ContractPortDouble implements
the OwnershipPort REQUIREMENT that the production adapter does not have; tests using it prove the evaluator logic only.
"""
import io
import random
import re
from types import SimpleNamespace

from PIL import Image, ImageDraw

from orchestrator import browser_verify as B
from orchestrator.chain import DesktopObservation, ObservedState
from test_chain import HOP1_UP, _one_hop

W, H = 1280, 720
S = W / 1920.0
TW, TH = 192, 108
PROJECT = "remote-desktop-operating-procedure-c9e06bd7"
REQ = B.BrowserVerifyRequest(project=PROJECT, run_id="trig_20261102T000000_abcd1234", requested_mode="browser_verify",
                             url=B.ALLOWED_URL, confirm_phrase=B.expected_confirm_phrase(PROJECT), leave_open_ack=B.expected_leave_open_phrase(PROJECT))
POLICY = B.BrowserVerifyPolicy(enabled=True, allowed_projects=frozenset({PROJECT}))


def _blocks(seed, w, h, block=6):
    r = random.Random(seed)
    sw, sh = -(-w // block), -(-h // block)
    small = Image.new("L", (sw, sh))
    small.putdata([r.randrange(30, 225) for _ in range(sw * sh)])
    return small.resize((sw * block, sh * block), Image.NEAREST).crop((0, 0, w, h))


def tile_image(mode, idx, t, w=TW, h=TH):
    base = _blocks(1000 + idx, w, h)
    if mode == "advancing":
        img = _blocks(int(t * 100) + idx * 7919, w, h)
    elif mode == "cut_once":
        img = _blocks(5 + idx, w, h) if t < 30 else _blocks(6 + idx, w, h)
    elif mode == "scroll":
        tall = _blocks(1000 + idx, w, h * 3)
        shift = (int(t // 3) * 8) % (2 * h)
        img = tall.crop((0, shift, w, shift + h))
    elif mode == "noisy_frozen":
        img = base.copy()
        px, r = img.load(), random.Random(int(t * 100))
        for _ in range(int(w * h * 0.02)):
            x, y = r.randrange(w), r.randrange(h)
            px[x, y] = max(0, min(255, px[x, y] + r.choice((-2, 2))))
    elif mode == "loading":
        img = Image.new("L", (w, h), 120)
    elif mode == "error":
        img = Image.new("L", (w, h), 60)
    else:
        img = base.copy()
    d = ImageDraw.Draw(img)
    if mode in ("spinner", "loading"):
        a = int(t * 90) % 360
        d.pieslice((w // 2 - 8, h // 2 - 8, w // 2 + 8, h // 2 + 8), a, a + 90, fill=255)
    elif mode == "clock":
        d.rectangle((w - 40, 2, w - 4, 16), fill=0)
        d.text((w - 38, 3), "%02d" % (int(t) % 100), fill=255)
    elif mode == "cursor":
        x = 10 + (int(t) * 13) % 150
        d.rectangle((x, 40, x + 4, 54), fill=255)
    elif mode == "error":
        d.line((0, 0, w, h), fill=255, width=3)
        d.line((0, h, w, 0), fill=255, width=3)
    return img.convert("RGB")


class DesktopSim:
    def __init__(self, clock, log, *, modes=None, streams=3, remembered="", preexisting_dialog=False, escape_works=True, super_r_works=True,
                 launch_fails=False, load_delay=4.0, url_ok=True, error_page=False, preexisting_chrome=False, prompt_after=None,
                 overlay=False, no_regions=False, steal_focus=False, region_perturb=None, unstable=False):
        self.clock, self.log = clock, log
        self.modes = modes or ["advancing"] * streams
        self.remembered, self.dialog_open, self.field, self.selected = remembered, preexisting_dialog, remembered if preexisting_dialog else "", False
        self.escape_works, self.super_r_works, self.launch_fails = escape_works, super_r_works, launch_fails
        self.load_delay, self.url_ok, self.error_page, self.prompt_after = load_delay, url_ok, error_page, prompt_after
        self.overlay, self.no_regions, self.steal_focus, self.region_perturb, self.unstable = overlay, no_regions, steal_focus, region_perturb, unstable
        self.windows = []
        self.executed, self.keys, self.typed_log, self.closed_by_key = [], [], [], []
        self.after_type = None
        if preexisting_chrome:
            self.windows.append({"kind": "chrome", "profile": "default-user-profile", "rect": (int(300 * S), int(200 * S), int(1000 * S), int(650 * S)),
                                 "born": -999.0, "url_ok": True, "error": False, "modes": ["advancing"] * 3, "id": "pre1"})

    # -- adapter contract -----------------------------------------------------------------------
    def key(self, combo):
        self.keys.append(combo)
        if combo == "super+r" and self.super_r_works and not self.dialog_open:
            self.dialog_open, self.field, self.selected = True, self.remembered, False
        elif combo == "ctrl+a" and self.dialog_open:
            self.selected = True
        elif combo == "Escape" and self.dialog_open and self.escape_works:
            self.remembered, self.dialog_open = self.field, False
        elif combo == "Return" and self.dialog_open:
            cmd = self.field
            self.executed.append(cmd)
            self.remembered, self.dialog_open = cmd, False
            self._exec(cmd)
        elif combo in ("alt+f4", "ctrl+w", "ctrl+shift+w") and self.windows:
            self.closed_by_key.append(self.windows.pop()["id"])

    def type(self, text):
        self.typed_log.append(text)
        if self.dialog_open:
            self.field = text if self.selected else self.field + text
            self.selected = False
        if self.after_type:
            self.after_type()

    def _exec(self, cmd):
        m = re.fullmatch(r"chrome --user-data-dir=%TEMP%\\(\S+) --no-first-run --no-default-browser-check --new-window "
                         r"--window-position=(\d+),(\d+) --window-size=(\d+),(\d+) (\S+)", cmd)
        if not m or self.launch_fails:
            return
        prof, x, y, w, h, url = m.group(1), *(int(m.group(i)) for i in range(2, 6)), m.group(6)
        win = {"kind": "chrome", "profile": prof, "rect": (int(x * S), int(y * S), int((x + w) * S), int((y + h) * S)), "born": self.clock.t,
               "url_ok": self.url_ok and url == B.ALLOWED_URL, "error": self.error_page, "modes": list(self.modes), "id": "w-" + prof}
        if self.steal_focus:
            self.windows.insert(0, win)
        else:
            self.windows.append(win)

    def prompt_active(self):
        return self.prompt_after is not None and self.clock.t >= self.prompt_after

    def top_chrome(self):
        for w in reversed(self.windows):
            if w["kind"] == "chrome":
                return w
        return None

    def loaded(self, w):
        return self.clock.t >= w["born"] + self.load_delay

    def tile_regions(self, w):
        x0, y0, x1, y1 = w["rect"]
        out = []
        for i, mode in enumerate(w["modes"]):
            shift = (int(self.clock.t // 3) * 30) % 90 if (self.unstable and i == 0) else 0
            tx = x0 + 20 + i * (TW + 16) + shift
            ty = y0 + 60
            out.append({"label": "Stream %d" % (i + 1), "x": tx, "y": ty, "w": TW, "h": TH, "_mode": mode})
        return out

    def screenshot(self):
        img = Image.new("RGB", (W, H), (30, 60, 90))
        d = ImageDraw.Draw(img)
        d.rectangle((0, H - 30, W, H), fill=(20, 20, 20))
        for w in self.windows:
            x0, y0, x1, y1 = w["rect"]
            d.rectangle((x0, y0, x1, y1), fill=(235, 235, 235), outline=(0, 0, 0))
            d.rectangle((x0, y0, x1, y0 + 28), fill=(60, 60, 60))
            if w["kind"] == "chrome" and self.loaded(w):
                for t in self.tile_regions(w):
                    img.paste(tile_image(t["_mode"], int(t["label"][-1]), self.clock.t), (t["x"], t["y"]))
                    d.text((t["x"], t["y"] - 14), t["label"], fill=(0, 0, 0))
                if self.overlay:
                    d.rectangle((x0 + 5, y0 + 40, x1 - 5, y0 + 110), fill=(250, 250, 0))
        if self.dialog_open:
            d.rectangle((20, H - 170, 460, H - 40), fill=(200, 210, 230), outline=(0, 0, 0))
            d.text((30, H - 150), "Run", fill=(0, 0, 0))
        if self.prompt_active():
            d.rectangle((400, 250, 880, 450), fill=(255, 220, 220), outline=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return SimpleNamespace(png=buf.getvalue())


class SimComputer:
    def __init__(self, sim, log):
        self.sim, self.log = sim, log

    def screenshot(self):
        self.log.append(("screenshot",))
        return self.sim.screenshot()

    def key(self, combo):
        self.log.append(("key", combo))
        self.sim.key(combo)

    def type(self, text):
        self.log.append(("type", text))
        self.sim.type(text)

    def type_secret(self, text):  # pragma: no cover - browser_verify never types secrets
        raise AssertionError("browser_verify must never type a secret")


class SimDesktopClassifier:
    def __init__(self, sim):
        self.sim = sim

    def classify(self, png, *, expect_host, expect_user, hint):
        s = self.sim
        if s.prompt_active():
            return DesktopObservation(state=ObservedState.UAC_CONSENT_PROMPT, confidence=0.95)
        if s.dialog_open:
            return DesktopObservation(state=ObservedState.RDP_CLIENT_RUN_DIALOG, confidence=0.95)
        return DesktopObservation(state=ObservedState.REMOTE_DESKTOP_READY, confidence=0.9, fullscreen=True)


class OraclePageClassifier:
    """STUB for the unimplemented model: sees only what is on screen (the top Chrome window); knows nothing about ownership."""

    def __init__(self, sim):
        self.sim, self.calls, self.on_call = sim, 0, None

    def describe(self, png):
        self.calls += 1
        if self.on_call:
            self.on_call(self.calls)
        s = self.sim
        if s.prompt_active():
            return B.PageObservation("unexpected_prompt", 0.95, prompt_kind="uac_consent_prompt")
        top = s.top_chrome()
        if top is None:
            return B.PageObservation("not_browser", 0.9)
        if top["error"]:
            return B.PageObservation("error_page", 0.9, address_ok=top["url_ok"])
        if not s.loaded(top):
            return B.PageObservation("loading", 0.9, address_ok=top["url_ok"])
        regs = [] if s.no_regions else s.tile_regions(top)
        states = {r["label"]: {"advancing": "playing", "frozen": "playing", "noisy_frozen": "playing", "loading": "loading", "error": "error"}.get(r["_mode"], "unknown") for r in regs}
        regs = [{k: v for k, v in r.items() if k != "_mode"} for r in regs]
        if s.region_perturb:
            regs = s.region_perturb(regs)
        return B.PageObservation("browser_page", 0.9, address_ok=top["url_ok"], regions=regs, region_states=states, overlay=s.overlay)


class ContractPortDouble:
    """CONTRACT TEST DOUBLE for B.OwnershipPort.  The PRODUCTION adapter has no such capability; this exists only to test the evaluator."""

    def __init__(self, sim, *, duplicate=False, rect_shift=0, close_works=True, list_raises=False):
        self.sim, self.duplicate, self.rect_shift, self.close_works, self.list_raises = sim, duplicate, rect_shift, close_works, list_raises
        self.close_calls = []

    def list_windows(self):
        if self.list_raises:
            raise RuntimeError("inventory failed")
        out = []
        for i, w in enumerate(self.sim.windows):
            if w["kind"] != "chrome":
                continue
            r = [int(round(v / S)) + self.rect_shift for v in w["rect"]]
            e = {"id": w["id"], "pid": 100 + i, "profile": w["profile"], "top_level": True, "visible": True, "rect": r}
            out.append(e)
            if self.duplicate and w["profile"].startswith(B.PROFILE_PREFIX):
                out.append({**e, "id": w["id"] + "-b"})
        return out

    def foreground_window_id(self):
        return self.sim.windows[-1]["id"] if self.sim.windows else None

    def close_window(self, window_id):
        self.close_calls.append(window_id)
        if self.close_works:
            self.sim.windows = [w for w in self.sim.windows if w["id"] != window_id]
        return True


def build(sim_kw=None, *, port=None, limits=None, policy=POLICY, nonce="a1b2c3d4", establish=True, page_cls=OraclePageClassifier):
    env = _one_hop(HOP1_UP)
    if establish:
        r = env.run()
        assert r.ok, (r.code, r.message)
    sim = DesktopSim(env.clock, env.log, **(sim_kw or {}))
    env.controller._computer = SimComputer(sim, env.log)
    env.controller._classifier = SimDesktopClassifier(sim)
    sess = B.ControllerSession(env.controller, port(sim) if callable(port) else port)
    page = page_cls(sim)
    ver = B.BrowserVerifier(sess, page, policy=policy, limits=limits, nonce_factory=lambda: nonce)
    return SimpleNamespace(env=env, sim=sim, sess=sess, page=page, ver=ver, mark=len(env.log))


def inputs_after(h):
    return [e for e in h.env.log[h.mark:] if e[0] in ("key", "type")]
