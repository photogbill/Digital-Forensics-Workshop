# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Read-only access to evidence, and the honest limits of software protection.

**A SOFTWARE WRITE BLOCKER ON WINDOWS IS NOT A HARDWARE WRITE BLOCKER.** A
tool that implies otherwise is worse than one with no write protection at
all, because it removes the operator's reason to reach for the real thing.
`HARDWARE_NOTICE` is the sentence every surface shows, permanently.

What this module can actually guarantee, in the order it matters:

1. **Read-only by construction.** Evidence is opened in exactly one place,
   `open_evidence`, with `O_RDONLY`. Every function in this package that
   writes, creates, renames or deletes anything is listed by name in
   `WRITERS`, with the kind of target it may touch — and
   `forensics_workshop/ratchet.py` walks the syntax tree of the whole
   package and fails the build on a write anywhere else. That is the
   guarantee that is enforceable, and it is enforceable because it is
   structural rather than a promise.

2. **Case and evidence never overlap.** `check_layout` refuses a case folder
   inside the evidence (it would be hashed as evidence, and every write the
   case makes would land in the evidence) and evidence inside the case.

3. **The USB `WriteProtect` policy, offered and then VERIFIED.** Setting a
   registry value is not the same claim as a device that refused a write.
   `verify_write_refused` attempts a real write against a device the
   operator has declared to be a TEST device, and reports what happened.
   The policy applies to USB mass storage attached after it was set; it does
   not cover Thunderbolt or NVMe enclosures that do not present as USB
   storage, internal disks, network volumes, or anything already mounted.

4. **Mount state, stated plainly.** `volume_state` reports whether the
   volume says it is read-only. A read-write volume that Windows has mounted
   can change — last-access times, the NTFS journal — while this tool reads
   nothing but bytes, and no tool can undo that afterwards.
"""

from __future__ import annotations

import errno as _errno
import os
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO, Iterable

from .errors import CaseLayoutError, CasePathError, EvidenceError
from .timeutil import utc_now

HARDWARE_NOTICE = (
    "Software protection is defence in depth, not a write blocker. For "
    "evidence that will be presented anywhere it matters, use a hardware "
    "write blocker. This tool guarantees that it never opens evidence for "
    "writing; it cannot stop Windows, another program, or the act of "
    "mounting a volume from changing it.")

#: The flags evidence is opened with. Named once so the ratchet can read
#: them, and so there is exactly one answer to "how is evidence opened".
READ_ONLY_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0)

#: Linux only: do not update the last-access time on read. The kernel allows
#: it only to the file's owner, so a PermissionError falls back to plain
#: read-only — and the ingest MEASURES whether atime moved rather than
#: assuming this flag worked.
NOATIME_FLAG = getattr(os, "O_NOATIME", 0)

#: EVERY function in the package allowed to write, create, rename, delete,
#: or connect to SQLite, and the only kind of target each may touch.
#:
#:   case        a path inside the open case folder, asserted at run time
#:               with `assert_case_path` — the ratchet checks the call is
#:               present in the function body
#:   app-state   the host application's own state file (ATK's case index);
#:               never a case, never evidence
#:   probe       the one deliberate write to a TEST device, refused unless
#:               the caller passes confirm_not_evidence=True
#:   host-policy the USB WriteProtect registry value
#:
#: A stale entry fails the ratchet too: a list that names functions which
#: no longer exist stops describing the code, and nobody notices.
WRITERS = {
    "blocker:verify_write_refused": "probe",
    "blocker:apply_usb_policy": "host-policy",
    "caseindex:CaseIndex._save": "app-state",
    "case:write_json_atomic": "case",
    "case:make_case_dirs": "case",
    "custody:CustodyLog._append": "case",
    "extract:copy_evidence_to_case": "case",
    "extract:copy_within_case": "case",
    "extract:copy_stream_to_case": "case",
    "index:connect": "case",
    "artefacts.browser:_open_working_copy": "case",
}


# ---------------------------------------------------------------------------
# 1. read-only by construction
# ---------------------------------------------------------------------------

def open_evidence(path) -> BinaryIO:
    """Open one evidence file for reading, and only for reading.

    The returned object is a buffered binary reader: it has no `write`, and
    the descriptor beneath it was opened `O_RDONLY`, so even a caller that
    reached for the raw descriptor could not write through it.
    """
    target = os.fspath(path)
    fd = None
    if NOATIME_FLAG:
        try:
            fd = os.open(target, READ_ONLY_FLAGS | NOATIME_FLAG)
        except PermissionError:
            fd = None
    if fd is None:
        fd = os.open(target, READ_ONLY_FLAGS)
    try:
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


# ---------------------------------------------------------------------------
# 2. case and evidence never overlap
# ---------------------------------------------------------------------------

def _norm(path) -> str:
    """Absolute, symlinks and junctions resolved where they exist, and
    case-folded on Windows — where `C:\\Case` and `c:\\case` are one
    folder and a comparison that disagreed would let a case into its own
    evidence."""
    real = os.path.realpath(os.fspath(path))
    return os.path.normcase(os.path.abspath(real))


def is_inside(child, parent) -> bool:
    """True when `child` is `parent` or lies beneath it."""
    c, p = _norm(child), _norm(parent)
    try:
        return os.path.commonpath([c, p]) == p
    except ValueError:            # different drives on Windows
        return False


def check_layout(case_root, source) -> None:
    """Refuse a case and an evidence source that overlap, in either direction."""
    if is_inside(case_root, source):
        raise CaseLayoutError(
            f"The case folder {case_root} is inside the evidence {source}. "
            "Ingesting would hash the case's own files as evidence, and "
            "every write the case makes would land inside the evidence. "
            "Put the case folder somewhere else.")
    if is_inside(source, case_root):
        raise CaseLayoutError(
            f"The evidence {source} is inside the case folder {case_root}. "
            "A case folder holds what the examiner produced, never the "
            "source; register evidence where it lives.")


def assert_case_path(case_root, target) -> Path:
    """The run-time half of the ratchet: a case writer's target is inside
    its case, or nothing is written."""
    if not is_inside(target, case_root):
        raise CasePathError(
            f"Refusing to write {target}: it is outside the case folder "
            f"{case_root}. Everything this engine writes during a case "
            "goes inside the case.")
    return Path(target)


def refuse_evidence_path(target, evidence_roots: Iterable) -> None:
    """Refuse a target that is, holds, or lies inside registered evidence."""
    for root in evidence_roots:
        if is_inside(target, root) or is_inside(root, target):
            raise CaseLayoutError(
                f"Refusing: {target} overlaps registered evidence {root}.")


# ---------------------------------------------------------------------------
# 4. mount state
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VolumeState:
    path: str
    volume: str
    filesystem: str
    serial: str
    drive_type: str
    read_only: bool | None
    basis: str
    warning: str

    def as_dict(self) -> dict:
        return asdict(self)


_DRIVE_TYPES = {0: "unknown", 1: "no-root", 2: "removable", 3: "fixed",
                4: "network", 5: "optical", 6: "ramdisk"}

RW_WARNING = (
    "This volume is mounted read-write. Reading through a mounted file "
    "system can still change it: last-access times, the NTFS journal, and "
    "anything Windows or another program does while it is attached. The "
    "hashes record what was read, not that nothing changed.")


def volume_state(path) -> VolumeState:
    """Is the volume holding `path` read-only, and what is it?

    Never raises: an answer of "unknown" is a real answer and is stated as
    one, because the absence of a warning must not be mistaken for a
    read-only volume.
    """
    try:
        if sys.platform == "win32":
            return _volume_state_windows(path)
        return _volume_state_posix(path)
    except Exception as exc:                          # noqa: BLE001
        return VolumeState(os.fspath(path), "", "", "", "unknown", None,
                           "unavailable",
                           f"Could not read the volume's state ({exc}); "
                           "treat it as writable.")


def _volume_state_windows(path) -> VolumeState:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR,
                                       wintypes.DWORD]
    k32.GetVolumePathNameW.restype = wintypes.BOOL
    k32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    k32.GetVolumeInformationW.restype = wintypes.BOOL
    k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    k32.GetDriveTypeW.restype = wintypes.UINT

    target = os.path.abspath(os.fspath(path))
    vol = ctypes.create_unicode_buffer(1024)
    if not k32.GetVolumePathNameW(target, vol, 1024):
        raise OSError(ctypes.get_last_error(), "GetVolumePathNameW failed")
    fs = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD()
    maxlen = wintypes.DWORD()
    flags = wintypes.DWORD()
    ok = k32.GetVolumeInformationW(vol.value, None, 0, ctypes.byref(serial),
                                   ctypes.byref(maxlen), ctypes.byref(flags),
                                   fs, 261)
    drive = _DRIVE_TYPES.get(int(k32.GetDriveTypeW(vol.value)), "unknown")
    if not ok:
        return VolumeState(target, vol.value, "", "", drive, None,
                           "GetVolumeInformationW",
                           "Windows would not describe this volume; treat "
                           "it as writable.")
    read_only = bool(flags.value & 0x00080000)       # FILE_READ_ONLY_VOLUME
    return VolumeState(target, vol.value, fs.value, f"{serial.value:08X}",
                       drive, read_only, "GetVolumeInformationW",
                       "" if read_only else RW_WARNING)


def _volume_state_posix(path) -> VolumeState:
    target = os.path.abspath(os.fspath(path))
    mount = target
    while not os.path.ismount(mount):
        parent = os.path.dirname(mount)
        if parent == mount:
            break
        mount = parent
    read_only = bool(os.statvfs(target).f_flag & getattr(os, "ST_RDONLY", 1))
    fstype = ""
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) > 2 and parts[1] == mount:
                    fstype = parts[2]
    except OSError:
        pass
    return VolumeState(target, mount, fstype, "", "unknown", read_only,
                       "statvfs", "" if read_only else RW_WARNING)


# ---------------------------------------------------------------------------
# 3. the USB WriteProtect policy, and verifying it
# ---------------------------------------------------------------------------

POLICY_KEY = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
POLICY_VALUE = "WriteProtect"

POLICY_SCOPE = (
    "Applies to USB mass storage attached AFTER it was set. It does not "
    "cover devices already mounted, Thunderbolt or NVMe enclosures that do "
    "not present as USB storage, internal disks, or network volumes. It is "
    "NOT VERIFIED until a test device refuses a write.")


@dataclass(frozen=True)
class PolicyState:
    supported: bool
    enabled: bool | None
    raw: int | None
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


def usb_policy_state() -> PolicyState:
    """Read the policy. Reading needs no elevation and changes nothing."""
    if sys.platform != "win32":
        return PolicyState(False, None, None,
                           "The USB WriteProtect policy is a Windows "
                           "registry setting; this platform has none.")
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, 0,
                            winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, POLICY_VALUE)
    except FileNotFoundError:
        return PolicyState(True, None, None,
                           "Not set: USB mass storage is writable.")
    except OSError as exc:
        return PolicyState(True, None, None,
                           f"Could not read the policy: {exc}")
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return PolicyState(True, None, None,
                           f"The policy holds an unexpected value: {value!r}")
    if raw == 1:
        return PolicyState(True, True, raw, "Set. " + POLICY_SCOPE)
    return PolicyState(True, False, raw,
                       "Present but off: USB mass storage is writable.")


@dataclass(frozen=True)
class PolicyChange:
    requested: bool
    applied: bool
    needs_elevation: bool
    error: str
    at: str
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


def apply_usb_policy(enabled: bool) -> PolicyChange:
    """Set or clear the policy. Needs an elevated process.

    Returns what happened rather than raising, because "you need to run this
    as Administrator" is an expected answer, not a failure of the tool.
    """
    at = utc_now()
    if sys.platform != "win32":
        return PolicyChange(enabled, False, False, "not Windows", at,
                            "This platform has no USB WriteProtect policy.")
    import winreg
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, POLICY_VALUE, 0, winreg.REG_DWORD,
                              1 if enabled else 0)
    except PermissionError as exc:
        return PolicyChange(enabled, False, True, str(exc), at,
                            "Windows refused: changing this policy needs "
                            "ATK to be running as Administrator.")
    except OSError as exc:
        return PolicyChange(enabled, False, False, str(exc), at,
                            "Windows refused the change.")
    if enabled:
        note = ("Applied. Re-attach USB devices for it to take effect, then "
                "verify it with a TEST device before trusting it. "
                + POLICY_SCOPE)
    else:
        note = "Cleared: USB mass storage attached from now on is writable."
    return PolicyChange(enabled, True, False, "", at, note)


@dataclass(frozen=True)
class WriteProbe:
    target: str
    at: str
    refused: bool
    error: str
    probe_created: bool
    probe_removed: bool | None
    volume: dict
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


def describe_oserror(exc: OSError) -> str:
    """`[WinError 19] The media is write protected` survives intact; a bare
    `[Errno 30]` gains its symbolic name, because a number alone is a
    lookup the operator should not have to do."""
    parts = []
    winerror = getattr(exc, "winerror", None)
    if winerror:
        parts.append(f"WinError {winerror}")
    elif exc.errno:
        parts.append(_errno.errorcode.get(exc.errno, f"errno {exc.errno}"))
    parts.append(exc.strerror or str(exc))
    return ": ".join(p for p in parts if p)


def verify_write_refused(target_dir, *, confirm_not_evidence: bool,
                         evidence_roots: Iterable = ()) -> WriteProbe:
    """ATTEMPT A WRITE, and report whether the device refused it.

    This is the only function in the engine that writes outside a case, and
    it exists because "the policy was applied" is not evidence of anything.
    Point it at a TEST device attached after the policy was set — never at
    evidence. `confirm_not_evidence` is keyword-only with no default, so
    the call site has to say so in words.

    If the write succeeds the device is NOT protected; the probe file is
    removed again and the result says whether that worked.
    """
    if confirm_not_evidence is not True:
        raise ValueError(
            "verify_write_refused attempts a real write. Point it at a test "
            "device, never at evidence, and pass confirm_not_evidence=True "
            "to say so.")
    target = Path(target_dir)
    if not target.is_dir():
        raise EvidenceError(f"{target} is not a folder that can be tested.")
    refuse_evidence_path(target, evidence_roots)
    at = utc_now()
    volume = volume_state(target).as_dict()
    probe = target / f".dfw-write-probe-{uuid.uuid4().hex}.tmp"
    try:
        fd = os.open(os.fspath(probe), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        return WriteProbe(
            os.fspath(target), at, True, describe_oserror(exc), False, None,
            volume,
            "REFUSED. The device refused a write at this time, through this "
            "path. That is the result that matters; the policy setting is "
            "not.")
    try:
        os.write(fd, b"dfw")
        write_error = ""
    except OSError as exc:
        write_error = describe_oserror(exc)
    finally:
        os.close(fd)
    try:
        os.remove(probe)
        removed = True
    except OSError:
        removed = False
    note = ("NOT PROTECTED. A probe file was created on this device, so "
            "writes are reaching it. ")
    if write_error:
        note += f"(Creating succeeded; writing data then failed: {write_error}) "
    note += ("The probe was removed again." if removed else
             f"The probe could not be removed and is still at {probe}.")
    return WriteProbe(os.fspath(target), at, False, write_error, True,
                      removed, volume, note)
