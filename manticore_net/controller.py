"""
iNNEXT SNES USB pad (DragonRise 0079:0011) plus generic Linux gamepads.

This pad does NOT speak Xbox codes (BTN_SOUTH / ABS_HAT0*). Linux exposes it as
"USB Gamepad" with joystick buttons 0-9 and analog ABS_X/ABS_Y (0-255, center 127).

Physical SNES labels  (evdev / js index)     UI action
---------------------------------------------------------
X  top          BTN_TRIGGER / 0              search
A  right        BTN_THUMB   / 1              inspect / confirm
B  bottom       BTN_THUMB2  / 2              back
Y  left         BTN_TOP     / 3              cycle filter
L               BTN_TOP2    / 4              previous tab
R               BTN_PINKIE  / 5              next tab
Select          BTN_BASE3   / 8              toggle capture
Start           BTN_BASE4   / 9              live / follow
D-pad U/D       ABS_Y                        move list
D-pad L/R       ABS_X                        page list
L / R           buttons 4 / 5                previous / next view

RetroArch udev: vendor 121 product 17, same button indices.
"""
from __future__ import annotations

import argparse
import select
import sys
import threading
import time
from collections.abc import Callable

try:
    from evdev import InputDevice, ecodes, list_devices
except Exception:  # pragma: no cover
    InputDevice = None
    ecodes = None
    list_devices = None

DRAGONRISE_VID = 0x0079
INNEXT_PIDS = {0x0011, 0x0126}

# Joystick-class codes used by 0079:0011
JS_X, JS_A, JS_B, JS_Y, JS_L, JS_R = 288, 289, 290, 291, 292, 293
JS_SELECT, JS_START = 296, 297
JS_PAGE_UP, JS_PAGE_DOWN = 294, 295  # unused face on some boards

AXIS_CENTER = 127
AXIS_PRESS = 40
AXIS_RELEASE = 20
REPEAT_INITIAL = 0.16
REPEAT_RATE = 0.04

INNEXT_KEYS = {
    JS_X: "search",
    JS_A: "inspect",
    JS_B: "back",
    JS_Y: "filter",
    JS_L: "tab_prev",
    JS_R: "tab_next",
    JS_SELECT: "capture",
    JS_START: "home",
    JS_PAGE_UP: "page_up",
    JS_PAGE_DOWN: "page_down",
}

def _generic_keys() -> dict[int, str]:
    if ecodes is None:
        return {}
    return {
        getattr(ecodes, "BTN_SOUTH", -1): "inspect",
        getattr(ecodes, "BTN_EAST", -1): "back",
        getattr(ecodes, "BTN_NORTH", -1): "search",
        getattr(ecodes, "BTN_WEST", -1): "filter",
        getattr(ecodes, "BTN_TL", -1): "tab_prev",
        getattr(ecodes, "BTN_TR", -1): "tab_next",
        getattr(ecodes, "BTN_SELECT", -1): "capture",
        getattr(ecodes, "BTN_START", -1): "home",
        getattr(ecodes, "BTN_MODE", -1): "home",
    }


def _is_innext(dev) -> bool:
    info = dev.info
    if info.vendor == DRAGONRISE_VID and info.product in INNEXT_PIDS:
        return True
    name = (dev.name or "").strip().lower()
    return "innext" in name or "dragonrise" in name or name == "usb gamepad"


def _looks_like_pad(dev) -> bool:
    if InputDevice is None:
        return False
    if _is_innext(dev):
        return True
    name = (dev.name or "").lower()
    if any(s in name for s in ("keyboard", "mouse", "hdmi", "consumer", "razer naga")):
        return False
    caps = dev.capabilities()
    keys = caps.get(ecodes.EV_KEY, [])
    if len(keys) > 48:
        return False
    wanted = {
        getattr(ecodes, "BTN_SOUTH", None),
        getattr(ecodes, "BTN_GAMEPAD", None),
        getattr(ecodes, "BTN_TRIGGER", None),
        getattr(ecodes, "BTN_JOYSTICK", None),
    }
    if any(k in keys for k in wanted if k is not None):
        return True
    return any(s in name for s in ("gamepad", "controller", "joystick", "innext"))


def find_pads() -> list:
    if list_devices is None:
        return []
    found = []
    for path in list_devices():
        try:
            dev = InputDevice(path)
        except OSError:
            continue
        if _looks_like_pad(dev):
            found.append(dev)
    found.sort(key=lambda d: (0 if _is_innext(d) else 1, d.path))
    return found


def axis_direction(value: int, current: int) -> int:
    if current == 0:
        if value <= AXIS_CENTER - AXIS_PRESS:
            return -1
        if value >= AXIS_CENTER + AXIS_PRESS:
            return 1
        return 0
    if abs(value - AXIS_CENTER) <= AXIS_RELEASE:
        return 0
    return -1 if value < AXIS_CENTER else 1


class PadThread(threading.Thread):
    def __init__(self, emit: Callable[[str], None], on_name: Callable[[str], None] | None = None):
        super().__init__(daemon=True, name="innext-pad")
        self.emit = emit
        self.on_name = on_name
        self.dev = None
        self.stop_flag = threading.Event()
        self.flavor = "none"
        self.keys: dict[int, str] = {}
        self.dx = 0
        self.dy = 0
        self._hold_t = {"x": 0.0, "y": 0.0}
        self._rep_t = {"x": 0.0, "y": 0.0}

    def run(self) -> None:
        if InputDevice is None:
            return
        pads = find_pads()
        if not pads:
            return
        self.dev = pads[0]
        for extra in pads[1:]:
            try:
                extra.close()
            except OSError:
                pass
        self.flavor = "innext" if _is_innext(self.dev) else "generic"
        self.keys = dict(INNEXT_KEYS if self.flavor == "innext" else _generic_keys())
        name = (self.dev.name or "gamepad").strip()
        if self.on_name:
            self.on_name(f"{name} [{self.flavor}]")
        try:
            self.dev.grab()
        except OSError:
            pass
        try:
            self._loop()
        finally:
            try:
                self.dev.ungrab()
            except OSError:
                pass
            try:
                self.dev.close()
            except OSError:
                pass

    def _fire_axis(self, now: float, axis: str, direction: int, neg: str, pos: str) -> None:
        if direction == 0 or self._hold_t[axis] == 0.0:
            return
        delay = REPEAT_INITIAL if (now - self._hold_t[axis]) < REPEAT_INITIAL + REPEAT_RATE else REPEAT_RATE
        if now - self._rep_t[axis] >= delay:
            self._rep_t[axis] = now
            self.emit(neg if direction < 0 else pos)

    def _handle_event(self, e) -> None:
        if e.type == ecodes.EV_KEY and e.value == 1:
            action = self.keys.get(e.code)
            if action:
                self.emit(action)
            return
        if e.type != ecodes.EV_ABS:
            return
        if e.code == ecodes.ABS_HAT0X:
            self._set_dir("x", -1 if e.value < 0 else 1 if e.value > 0 else 0)
            return
        if e.code == ecodes.ABS_HAT0Y:
            self._set_dir("y", -1 if e.value < 0 else 1 if e.value > 0 else 0)
            return
        if e.code == ecodes.ABS_X:
            self._set_dir("x", axis_direction(e.value, self.dx))
            return
        if e.code == ecodes.ABS_Y:
            self._set_dir("y", axis_direction(e.value, self.dy))

    def _set_dir(self, axis: str, new: int) -> None:
        old = self.dx if axis == "x" else self.dy
        if new == old:
            return
        if axis == "x":
            self.dx = new
        else:
            self.dy = new
        if new == 0:
            self._hold_t[axis] = 0.0
            self._rep_t[axis] = 0.0
            return
        now = time.monotonic()
        self._hold_t[axis] = now
        self._rep_t[axis] = now
        self.emit("left" if axis == "x" and new < 0 else "right" if axis == "x" else "up" if new < 0 else "down")

    def _loop(self) -> None:
        fd = self.dev.fd
        while not self.stop_flag.is_set():
            ready, _, _ = select.select([fd], [], [], 0.016)
            if ready:
                try:
                    for e in self.dev.read():
                        self._handle_event(e)
                except (OSError, BlockingIOError):
                    break
            now = time.monotonic()
            self._fire_axis(now, "x", self.dx, "left", "right")
            self._fire_axis(now, "y", self.dy, "up", "down")

    def stop(self) -> None:
        self.stop_flag.set()


def watch() -> int:
    if InputDevice is None:
        print("evdev is not installed", file=sys.stderr)
        return 1
    pads = find_pads()
    if not pads:
        print("No gamepad found. Plug in the iNNEXT (USB Gamepad / DragonRise 0079:0011).")
        print("This process needs read access to /dev/input/event* (sudo or group input).")
        return 1
    for d in pads:
        flavor = "innext" if _is_innext(d) else "generic"
        print(f"{d.path}  {d.name!r}  vid={d.info.vendor:#06x} pid={d.info.product:#06x}  {flavor}")
    print("Press buttons. Ctrl+C to stop.")
    t0 = time.monotonic()

    def emit(action: str) -> None:
        print(f"{time.monotonic() - t0:7.3f}  {action}")

    pad = PadThread(emit)
    pad.start()
    try:
        while pad.is_alive():
            time.sleep(0.2)
    except KeyboardInterrupt:
        print()
    pad.stop()
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe / watch the iNNEXT controller mapping")
    ap.add_argument("--watch", action="store_true", help="emit mapped actions until Ctrl+C")
    args = ap.parse_args()
    if args.watch:
        raise SystemExit(watch())
    if InputDevice is None:
        print("evdev is not installed")
        raise SystemExit(1)
    pads = find_pads()
    if not pads:
        print("No gamepad found")
        raise SystemExit(1)
    for d in pads:
        flavor = "innext" if _is_innext(d) else "generic"
        print(f"{d.path}\t{d.name.strip()}\tvid={d.info.vendor:#06x}\tpid={d.info.product:#06x}\t{flavor}")


if __name__ == "__main__":
    main()
