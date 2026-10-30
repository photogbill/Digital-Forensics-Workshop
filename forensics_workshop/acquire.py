# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Imaging a drive — what FTK Imager does, inside the engine (Bill, 2026-10-29).

A physical drive (or one volume of it) is read once, through the one
read-only door (`blocker.open_evidence`), and written as an EnCase E01 set or
a RAW/DD image — one file or split. MD5, SHA-1 and SHA-256 come out of the
same read. The image is then read back through the engine's own readers and
hashed again: an image whose hashes do not match what was read is reported,
never quietly registered. In a case, the acquisition is custody-recorded
and the image registered as evidence by the same act.

**THE SOURCE IS NEVER OPENED FOR WRITING.** It goes through
`blocker.open_evidence` like every other piece of evidence. On Windows the
drive list is built with read-only device queries, and the only function
that may call `CreateFileW` / `DeviceIoControl` (`_win_query`) refuses any
access but none-or-read and any control code not on `READ_ONLY_IOCTLS` —
the ratchet checks that guard is in its body.

**EVERY BYTE THIS MODULE WRITES GOES TO THE DESTINATION THE EXAMINER CHOSE.**
Three writers (`_make_destination`, `_open_output`, `_write_log`), each of
which calls `assert_acquisition_path` first. The destination is refused when
it is on the drive being imaged, inside a case folder, inside registered
evidence, or not empty — an acquisition never overwrites a file and never
mixes its segments with anything else.

**IT IS STILL NOT A WRITE BLOCKER.** Reading a drive through Windows means
Windows has seen it: it may have mounted its volumes and touched them
(last-access times, a journal replay) before this code opened it. That is
`blocker.HARDWARE_NOTICE`, and the log says it. For evidence that matters,
attach the drive through a hardware write blocker and say which one — the
log records the examiner's words.

**UNREADABLE SECTORS** are retried one sector at a time, then written as
zeros, listed by sector in the log, in custody and in the E01's `error2`
section — and the hashes are of what was written. FTK Imager and EnCase
behave the same way; the difference here is that the list is never hidden.

**IMAGING THE RUNNING SYSTEM DISK** is allowed and warned: files change while
they are read, so the result is a smear across time, not a snapshot.
"""

from __future__ import annotations

import os
import platform
import queue
import re
import shutil
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import __version__
from . import blocker, ewfwrite, hashing
from . import image as _image
from .errors import AcquisitionError, Cancelled
from .timeutil import utc_now

FORMATS = ("e01", "raw")
COMPRESSIONS = tuple(ewfwrite.COMPRESSION)
#: Bytes asked of the source per read. A multiple of every sector size.
READ_BLOCK = 1 << 20
#: Under 2 GiB, so every table offset fits without a base — what every EWF
#: reader understands — and under FAT32's 4 GiB file limit.
DEFAULT_SEGMENT = 2000 * (1 << 20)
DEFAULT_RETRIES = 2
#: A run of unreadable bytes this long, back to back, stops the run: a drive
#: that has died or been unplugged must not become a "verified" image of
#: zeros (review of the imager, 2026-10-29). A setting (`max_bad_run`).
MAX_BAD_RUN = 1 << 30
#: Names Windows keeps at the root of every volume — a freshly wiped drive's
#: root still holds them, and it is still an empty destination.
ROOT_NOISE = {"system volume information", "$recycle.bin", "recycler"}
#: How many unreadable-sector runs custody records in full (all are in the log).
CUSTODY_BAD_RUNS = 200

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")

# -- Windows read-only device queries ---------------------------------------
GENERIC_READ = 0x80000000
FILE_SHARE_READ, FILE_SHARE_WRITE = 0x1, 0x2
OPEN_EXISTING = 3
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
#: The only control codes `_win_query` will send. Each one only REPORTS.
READ_ONLY_IOCTLS = {
    IOCTL_STORAGE_QUERY_PROPERTY: "IOCTL_STORAGE_QUERY_PROPERTY",
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
    IOCTL_DISK_GET_LENGTH_INFO: "IOCTL_DISK_GET_LENGTH_INFO",
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
}
BUS_TYPES = {0: "unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394",
             5: "SSA", 6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI",
             10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "virtual",
             15: "file-backed virtual", 16: "Storage Spaces", 17: "NVMe",
             18: "SCM", 19: "UFS"}

ELEVATION_SENTENCE = (
    "Reading a drive needs ATK (or this command) to run as Administrator. "
    "Windows refuses a raw read of a disk to anyone else.")
ROOT_SENTENCE = ("Reading a drive needs root (or membership of the `disk` "
                 "group) on this system.")
SYSTEM_DISK_WARNING = (
    "This drive holds the running operating system. Files on it change while "
    "it is read, so the image is a smear across time, not a snapshot. For "
    "evidence, boot from other media or remove the drive and attach it "
    "through a hardware write blocker.")
VOLUME_WARNING = (
    "This is ONE VOLUME, not the whole disk: no partition table, no other "
    "partitions, and no unallocated space outside this volume.")


# ---------------------------------------------------------------------------
# guards — the run-time half of the ratchet
# ---------------------------------------------------------------------------

def assert_query_only(access: int, code: int) -> int:
    """`_win_query`'s guard: open with no access or read access only, and
    send only a control code that reports."""
    if access not in (0, GENERIC_READ):
        raise AcquisitionError(
            f"Refusing a device handle with access 0x{access:08X}: drive "
            "queries open with no access or read access only.")
    if code not in READ_ONLY_IOCTLS:
        raise AcquisitionError(
            f"Refusing control code 0x{code:08X}: only the read-only queries "
            f"{sorted(READ_ONLY_IOCTLS.values())} are ever sent to a drive.")
    return code


def _case_above(path: Path) -> Path | None:
    for folder in (path, *path.parents):
        try:
            if (folder / "case.json").is_file():
                return folder
        except OSError:
            continue
    return None


def assert_acquisition_path(destination, target) -> Path:
    """Every acquisition write's guard: the target is inside the destination
    the examiner chose, and that destination is not inside a case."""
    dest = Path(os.path.abspath(os.fspath(destination)))
    if not blocker.is_inside(target, dest):
        raise AcquisitionError(
            f"Refusing to write {target}: it is outside the acquisition "
            f"destination {dest}.")
    case = _case_above(dest)
    if case is not None:
        raise AcquisitionError(
            f"Refusing: the destination {dest} is inside the case at {case}. "
            "An image is evidence, and evidence is never kept inside a case "
            "folder — choose a folder beside the case.")
    return Path(target)


# ---------------------------------------------------------------------------
# the writers — every file this module writes passes through these three
# ---------------------------------------------------------------------------

def _make_destination(destination) -> Path:
    dest = assert_acquisition_path(destination, destination)
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def _open_output(destination, path):
    """A NEW file for the image, never an existing one ("xb")."""
    return open(assert_acquisition_path(destination, path), "xb")


def _write_log(destination, path, text: str) -> None:
    target = assert_acquisition_path(destination, path)
    with open(target, "x", encoding="utf-8", newline="\r\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


# ---------------------------------------------------------------------------
# the drives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Drive:
    path: str                 # \\.\PhysicalDrive1 | \\.\E: | /dev/sdb
    kind: str                 # physical | volume
    number: int | None
    size: int
    sector_size: int
    model: str = ""
    vendor: str = ""
    serial: str = ""
    bus: str = ""
    removable: bool | None = None
    volumes: tuple = ()
    system: bool = False
    note: str = ""
    #: Where the bytes are actually read from, when that is not `path`: a
    #: Windows volume is read through its PHYSICAL disk, from the volume's
    #: first byte, because a read through `\\.\E:` stops where the file
    #: system says the volume ends — NTFS one sector early, where its backup
    #: boot sector is.
    read_path: str = ""
    read_offset: int = 0

    def as_dict(self) -> dict:
        data = asdict(self)
        data["volumes"] = list(self.volumes)
        return data

    @property
    def reader(self) -> str:
        return self.read_path or self.path

    def label(self) -> str:
        name = " ".join(p for p in (self.vendor, self.model) if p) or "drive"
        vols = f" [{', '.join(self.volumes)}]" if self.volumes else ""
        sys_ = " — SYSTEM DISK" if self.system else ""
        return (f"{self.path}  {name}  {_human(self.size)}"
                f"{'  ' + self.bus if self.bus else ''}{vols}{sys_}")


def _human(n: int) -> str:
    n = float(n or 0)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def is_windows() -> bool:
    return sys.platform == "win32"


def is_elevated() -> bool:
    """Administrator on Windows, root elsewhere. False when it cannot tell."""
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:                                     # noqa: BLE001
        return False


def _win_query(path: str, code: int, *, out_size: int = 4096,
               in_buf: bytes = b"", access: int = 0) -> bytes | None:
    """One read-only DeviceIoControl, or None when Windows says no. THE ONLY
    place in the engine that calls CreateFileW or DeviceIoControl."""
    assert_query_only(access, code)
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                    wintypes.LPVOID, wintypes.DWORD,
                                    wintypes.LPVOID, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD),
                                    wintypes.LPVOID]
    k32.DeviceIoControl.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    handle = k32.CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             None, OPEN_EXISTING, 0, None)
    if not handle or handle == invalid:
        return None
    try:
        inb = ctypes.create_string_buffer(in_buf, len(in_buf)) if in_buf else None
        out = ctypes.create_string_buffer(out_size)
        got = wintypes.DWORD(0)
        ok = k32.DeviceIoControl(handle, code, inb, len(in_buf), out,
                                 out_size, ctypes.byref(got), None)
        return out.raw[:got.value] if ok else None
    finally:
        k32.CloseHandle(handle)


def _ascii_at(raw: bytes, offset: int) -> str:
    if not 0 < offset < len(raw):
        return ""
    end = raw.find(b"\x00", offset)
    return raw[offset:end if end >= 0 else len(raw)].decode(
        "ascii", "replace").strip()


def _win_descriptor(path: str) -> dict:
    query = struct.pack("<II", 0, 0) + b"\x00" * 4   # StorageDeviceProperty
    raw = _win_query(path, IOCTL_STORAGE_QUERY_PROPERTY, in_buf=query,
                     out_size=1024)
    if not raw or len(raw) < 36:
        return {}
    (_v, _s, _dt, _dm, removable, _cq, v_off, p_off, _r_off, s_off,
     bus, _raw_len) = struct.unpack_from("<IIBBBBIIIIII", raw, 0)
    return {"vendor": _ascii_at(raw, v_off), "model": _ascii_at(raw, p_off),
            "serial": _ascii_at(raw, s_off),
            "bus": BUS_TYPES.get(bus, f"bus {bus}"),
            "removable": bool(removable)}


def _win_geometry(path: str) -> tuple[int, int] | None:
    """(disk size, bytes per sector) — no read access needed."""
    raw = _win_query(path, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, out_size=256)
    if not raw or len(raw) < 32:
        return None
    _cyl, _media, _tpc, _spt, bps, size = struct.unpack_from("<qIIIIq", raw, 0)
    return int(size), int(bps or 512)


def _win_length(path: str) -> int | None:
    raw = _win_query(path, IOCTL_DISK_GET_LENGTH_INFO, out_size=8,
                     access=GENERIC_READ)
    return struct.unpack_from("<q", raw, 0)[0] if raw and len(raw) >= 8 else None


def _win_extent_list(volume_path: str) -> list[tuple[int, int, int]]:
    """(disk number, first byte on that disk, length) for each extent."""
    raw = _win_query(volume_path, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                     out_size=1024)
    if not raw or len(raw) < 8:
        return []
    (count,) = struct.unpack_from("<I", raw, 0)
    out = []
    for i in range(min(count, (len(raw) - 8) // 24)):
        number, start, length = struct.unpack_from("<I4xqq", raw, 8 + 24 * i)
        out.append((int(number), int(start), int(length)))
    return out


def _win_extents(volume_path: str) -> list[int]:
    return [disk for disk, _start, _length in _win_extent_list(volume_path)]


def _win_letters() -> list[str]:
    import ctypes
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [f"{chr(65 + i)}:" for i in range(26) if mask & (1 << i)]


def _list_windows() -> list[Drive]:
    letters_on: dict[int, list[str]] = {}
    for letter in _win_letters():
        for number in _win_extents(f"\\\\.\\{letter}"):
            letters_on.setdefault(number, []).append(letter)
    system = os.environ.get("SystemDrive", "C:").upper()
    drives = []
    for number in range(64):
        path = f"\\\\.\\PhysicalDrive{number}"
        geo = _win_geometry(path)
        if geo is None:
            continue
        size, bps = geo
        info = _win_descriptor(path)
        vols = tuple(letters_on.get(number, ()))
        drives.append(Drive(
            path=path, kind="physical", number=number, size=size,
            sector_size=bps, model=info.get("model", ""),
            vendor=info.get("vendor", ""), serial=info.get("serial", ""),
            bus=info.get("bus", ""), removable=info.get("removable"),
            volumes=vols, system=system in vols))
    return drives


def _sys_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _linux_partition_parents() -> dict[str, str]:
    parents = {}
    root = Path("/sys/block")
    for disk in (root.iterdir() if root.is_dir() else ()):
        for child in disk.iterdir():
            if (child / "partition").is_file():
                parents[child.name] = disk.name
    return parents


def _list_linux() -> list[Drive]:
    root = Path("/sys/block")
    if not root.is_dir():
        return []
    parents = _linux_partition_parents()
    mounts: dict[str, list[str]] = {}
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                dev, point = line.split()[:2]
                name = os.path.basename(dev)
                disk = parents.get(name, name)
                mounts.setdefault(disk, []).append(point)
    except OSError:
        pass
    drives = []
    for disk in sorted(root.iterdir()):
        if disk.name.startswith(("ram", "zram", "loop", "dm-", "md", "sr")):
            continue
        sectors = _sys_text(disk / "size")
        if not sectors.isdigit() or int(sectors) == 0:
            continue
        bps = _sys_text(disk / "queue" / "logical_block_size")
        vols = tuple(mounts.get(disk.name, ()))
        drives.append(Drive(
            path=f"/dev/{disk.name}", kind="physical", number=None,
            size=int(sectors) * 512, sector_size=int(bps) if bps.isdigit() else 512,
            model=_sys_text(disk / "device" / "model"),
            vendor=_sys_text(disk / "device" / "vendor"),
            serial=_sys_text(disk / "device" / "serial"),
            removable=_sys_text(disk / "removable") == "1",
            volumes=vols, system="/" in vols))
    return drives


def list_drives() -> list[Drive]:
    """Every drive this machine shows, read with queries that change nothing.
    Never raises: a drive that cannot be described is left out."""
    try:
        return _list_windows() if is_windows() else _list_linux()
    except Exception:                                     # noqa: BLE001
        return []


# -- which physical disk holds what ------------------------------------------

def normalise_source(source: str) -> str:
    """`PhysicalDrive1` -> `\\\\.\\PhysicalDrive1`; `E:` -> `\\\\.\\E:` on
    Windows. Anything else is returned as given."""
    text = str(source).strip()
    if is_windows():
        if re.fullmatch(r"(?i)physicaldrive\d+", text):
            return "\\\\.\\" + text
        if re.fullmatch(r"[A-Za-z]:\\?", text):
            return "\\\\.\\" + text[:2].upper()
    return text


def source_kind(source: str) -> str:
    s = normalise_source(source)
    if re.fullmatch(r"(?i)\\\\\.\\physicaldrive\d+", s):
        return "physical"
    if re.fullmatch(r"\\\\\.\\[A-Za-z]:", s):
        return "volume"
    if s.startswith("/dev/"):
        return "volume" if _linux_partition_parents().get(
            os.path.basename(s)) else "physical"
    return "file"


def disks_of_path(path) -> set:
    """The physical disks holding `path`'s volume, as source paths; an empty
    set when that cannot be told (the caller warns rather than guesses)."""
    try:
        if is_windows():
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR,
                                               wintypes.LPWSTR, wintypes.DWORD]
            buf = ctypes.create_unicode_buffer(1024)
            # A junction or symlink is followed first: GetVolumePathNameW
            # does not, so D:\\link -> E:\\x would be judged to be on D:.
            probe = Path(os.path.realpath(os.fspath(path)))
            while not probe.exists() and probe.parent != probe:
                probe = probe.parent
            if not k32.GetVolumePathNameW(os.fspath(probe), buf, 1024):
                return set()
            volume = buf.value.rstrip("\\")
            if not re.fullmatch(r"[A-Za-z]:", volume):
                return set()
            return {f"\\\\.\\PhysicalDrive{n}"
                    for n in _win_extents(f"\\\\.\\{volume.upper()}")}
        probe = Path(os.path.realpath(os.fspath(path)))
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        st = os.stat(probe)
        link = Path(f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}")
        if not link.exists():
            return set()
        real = Path(os.path.realpath(link))
        name = real.parent.name if (real / "partition").is_file() else real.name
        return {f"/dev/{name}"}
    except Exception:                                     # noqa: BLE001
        return set()


def disks_of_source(source: str) -> set:
    s = normalise_source(source)
    kind = source_kind(s)
    if kind == "physical":
        return {s}
    if kind == "volume" and is_windows():
        return {f"\\\\.\\PhysicalDrive{n}" for n in _win_extents(s)}
    if kind == "volume":
        parent = _linux_partition_parents().get(os.path.basename(s))
        return {f"/dev/{parent}"} if parent else {s}
    return disks_of_path(s)


def _describe_windows_volume(s: str) -> Drive:
    """A volume, to be read through its physical disk from its first byte —
    every sector of the volume, the backup boot sector included."""
    extents = _win_extent_list(s)
    if len(extents) != 1:
        raise AcquisitionError(
            f"{s} " + ("spans several disks" if extents else
                       "is not on a disk Windows can name (a virtual, "
                       "encrypted-container or file-backed volume)")
            + ", so it cannot be read as one stretch of one disk. Image the "
              "physical drive instead.")
    disk, start, length = extents[0]
    phys = f"\\\\.\\PhysicalDrive{disk}"
    geo = _win_geometry(phys)
    bps = geo[1] if geo else 512
    parent = next((d for d in list_drives() if d.number == disk), None)
    letter = s[-2:].upper()
    system = letter == os.environ.get("SystemDrive", "C:").upper()
    return Drive(
        path=s, kind="volume", number=disk, size=int(length), sector_size=bps,
        model=parent.model if parent else "", vendor=parent.vendor if parent else "",
        serial=parent.serial if parent else "", bus=parent.bus if parent else "",
        removable=parent.removable if parent else None, volumes=(letter,),
        system=system, read_path=phys, read_offset=int(start),
        note=f"read through {phys} from byte {start:,} — the volume's own "
             "handle stops where its file system ends")


def describe_source(source: str) -> Drive:
    """What is about to be read: its size and sector size, and whatever the
    drive says about itself. Raises AcquisitionError when it cannot be read."""
    s = normalise_source(source)
    kind = source_kind(s)
    listed = next((d for d in list_drives() if d.path.lower() == s.lower()), None)
    size, bps = None, (listed.sector_size if listed else 512)
    if is_windows() and kind == "volume":
        return _describe_windows_volume(s)
    if is_windows() and kind in ("physical", "volume"):
        geo = _win_geometry(s)
        if geo is not None:
            size, bps = geo if kind == "physical" else (None, geo[1])
        if size is None:
            size = _win_length(s)
        if size is None:
            raise AcquisitionError(
                f"Windows would not say how big {s} is. "
                + ("" if is_elevated() else ELEVATION_SENTENCE))
    else:
        try:
            with blocker.open_evidence(s) as fh:
                size = fh.seek(0, os.SEEK_END)
        except OSError as exc:
            denied = isinstance(exc, PermissionError)
            hint = ""
            if denied and kind != "file" and not is_elevated():
                hint = " " + (ELEVATION_SENTENCE if is_windows()
                              else ROOT_SENTENCE)
            raise AcquisitionError(
                f"{s} cannot be opened for reading: "
                f"{blocker.describe_oserror(exc)}.{hint}") from exc
    if listed is not None:
        return Drive(**{**listed.as_dict(), "volumes": listed.volumes,
                        "size": int(size), "sector_size": int(bps),
                        "kind": kind if kind != "file" else listed.kind})
    return Drive(path=s, kind=kind, number=None, size=int(size),
                 sector_size=int(bps))


# ---------------------------------------------------------------------------
# the plan — everything checked before a byte is written
# ---------------------------------------------------------------------------

@dataclass
class Plan:
    source: str
    drive: Drive | None
    destination: str
    base_name: str
    fmt: str
    compression: str
    segment_bytes: int | None
    refusals: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refusals

    def first_output(self) -> str:
        base = os.path.join(self.destination, self.base_name)
        if self.fmt == "e01":
            return base + ".E01"
        size = self.drive.size if self.drive else 0
        split = self.segment_bytes is not None and size > self.segment_bytes
        return base + (".001" if split else ".dd")

    def as_dict(self) -> dict:
        data = asdict(self)
        data["drive"] = self.drive.as_dict() if self.drive else None
        data["first_output"] = self.first_output()
        return data


def check_plan(source: str, destination, base_name: str, *, fmt: str = "e01",
               compression: str = "fast",
               segment_bytes: int | None = DEFAULT_SEGMENT,
               case=None) -> Plan:
    """Every reason not to start, and every warning, before anything runs."""
    src = normalise_source(source)
    dest = Path(os.path.abspath(os.fspath(destination)))
    plan = Plan(src, None, os.fspath(dest), str(base_name or "").strip(),
                (fmt or "").lower(), (compression or "").lower(),
                segment_bytes if segment_bytes else None)
    no = plan.refusals.append
    if plan.fmt not in FORMATS:
        no(f"{fmt!r} is not a format this imager writes ({', '.join(FORMATS)}).")
    if plan.fmt == "e01" and plan.compression not in COMPRESSIONS:
        no(f"{compression!r} is not a compression ({', '.join(COMPRESSIONS)}).")
    if not _NAME.match(plan.base_name):
        no("The image name must start with a letter or digit and use only "
           "letters, digits, space, dot, underscore and hyphen (up to 80).")
    if plan.segment_bytes is not None and plan.segment_bytes < (1 << 20):
        no("A segment must be at least 1 MB (or 0 for one file).")
    kind = source_kind(src)
    if kind == "file":
        no(f"{src} is a file, not a drive. To register an existing image, use "
           "Add a disk image on the Disk Image page instead.")
        return plan
    if is_windows() and not is_elevated():
        no(ELEVATION_SENTENCE)
        return plan
    try:
        plan.drive = describe_source(src)
    except AcquisitionError as exc:
        no(str(exc))
        return plan
    drive = plan.drive
    if drive.size <= 0:
        no(f"{src} reports a size of zero — there is nothing to image (an "
           "empty card reader slot reads like this).")
    if plan.fmt == "e01" and drive.size % drive.sector_size:
        no(f"{src} is {drive.size:,} bytes, not a whole number of "
           f"{drive.sector_size}-byte sectors; write RAW instead.")
    if drive.system:
        plan.warnings.append(SYSTEM_DISK_WARNING)
    if kind == "volume":
        plan.warnings.append(VOLUME_WARNING)
    # -- the destination ---------------------------------------------------
    if dest.exists() and not dest.is_dir():
        no(f"{dest} exists and is not a folder.")
    elif dest.is_dir() and any(
            p for p in dest.iterdir()
            if not (dest.parent == dest and p.name.lower() in ROOT_NOISE)):
        no(f"{dest} is not empty. Choose an empty folder (or a new one): an "
           "acquisition never overwrites a file or mixes its segments with "
           "anything else.")
    above = _case_above(dest)
    if above is not None:
        no(f"The destination is inside the case at {above}. An image is "
           "evidence and is never kept inside a case folder; choose a folder "
           "beside it.")
    if case is not None:
        if blocker.is_inside(case.root, dest):
            no(f"The case folder {case.root} is inside the destination.")
        for root in case.evidence_roots():
            if blocker.is_inside(dest, root) or blocker.is_inside(root, dest):
                no(f"The destination overlaps registered evidence {root}.")
                break
    src_disks = ({drive.reader.lower()} if drive.read_path
                 else {d.lower() for d in disks_of_source(src)})
    dst_disks = {d.lower() for d in disks_of_path(os.path.realpath(dest))}
    if not src_disks:
        plan.warnings.append(
            "Which physical drive the source is on could not be told, so the "
            "destination could not be checked against it. Make sure they are "
            "different drives.")
    if src_disks & dst_disks:
        no("The destination is on the drive being imaged. Writing there would "
           "change the evidence while it is being read. Choose a folder on "
           "another drive.")
    elif not dst_disks:
        plan.warnings.append(
            "Which physical drive holds the destination could not be told, so "
            "it could not be checked against the source. Make sure it is a "
            "different drive.")
    if plan.fmt == "e01" and plan.segment_bytes:
        room = ewfwrite.MAX_SEGMENTS * plan.segment_bytes
        if drive.size * 1.002 > room:
            no(f"{_human(drive.size)} in {_human(plan.segment_bytes)} segments "
               f"needs more than the {ewfwrite.MAX_SEGMENTS:,} segment names "
               "EWF has (E01-ZZZ). Choose bigger segments or one file.")
    probe = dest
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        free = None
    if free is not None:
        if plan.fmt == "raw" and free < drive.size + (1 << 20):
            no(f"The destination has {_human(free)} free; a RAW image of this "
               f"drive needs {_human(drive.size)}.")
        elif plan.fmt == "e01" and free < drive.size:
            plan.warnings.append(
                f"The destination has {_human(free)} free and the drive is "
                f"{_human(drive.size)}. E01 compresses, but a full or "
                "encrypted drive barely does — the run may run out of room.")
    return plan


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

@dataclass
class AcquisitionResult:
    state: str                         # completed | cancelled | failed
    source: dict
    destination: str
    fmt: str
    compression: str
    segments: list
    hashes: dict
    bytes_read: int
    bad_sectors: list                  # [(first sector, count)]
    verified: bool | None
    verification: dict
    started_at: str
    finished_at: str
    elapsed_s: float
    log: str
    evidence_id: str = ""
    warnings: list = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


class _RawSink:
    """RAW/DD output: one `.dd`, or `.001`, `.002`, … of `segment_bytes`."""

    def __init__(self, destination, base: str, size: int,
                 segment_bytes: int | None) -> None:
        self.destination = destination
        self.base = base
        self.split = segment_bytes is not None and size > segment_bytes
        self.segment_bytes = segment_bytes if self.split else None
        self.paths: list[str] = []
        self._fh = None
        self._room = 0

    def _next(self) -> None:
        if self._fh is not None:
            self._fh.close()
        n = len(self.paths) + 1
        path = (f"{self.base}.{n:03d}" if self.split else f"{self.base}.dd")
        self._fh = _open_output(self.destination, path)
        self.paths.append(path)
        self._room = self.segment_bytes or (1 << 62)

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while len(view):
            if self._fh is None or self._room == 0:
                self._next()
            take = min(self._room, len(view))
            self._fh.write(view[:take])
            self._room -= take
            view = view[take:]

    def finish(self, *_args) -> list[str]:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None
        return list(self.paths)

    def abandon(self) -> list[str]:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        return list(self.paths)


class _Stopped(Exception):
    """The reader was told to stop mid-block."""


class _BadMap:
    """Unreadable sectors as (first sector, count) RUNS, merged as they come
    — never one entry per sector: a dying terabyte would otherwise be tens of
    gigabytes of Python ints (review, 2026-10-29). Also tracks the longest
    unbroken run, so a drive that has gone is told from one with bad spots."""

    def __init__(self) -> None:
        self.runs: list[list[int]] = []
        self.sectors = 0
        self.consecutive_bytes = 0

    def add(self, sector: int, sector_size: int) -> None:
        if self.runs and self.runs[-1][0] + self.runs[-1][1] == sector:
            self.runs[-1][1] += 1
        else:
            self.runs.append([sector, 1])
        self.sectors += 1
        self.consecutive_bytes += sector_size

    def good(self) -> None:
        self.consecutive_bytes = 0

    def as_runs(self) -> list[tuple[int, int]]:
        return [(a, b) for a, b in self.runs]


def _read_exact(raw, n: int) -> bytes:
    """Up to `n` bytes from an UNBUFFERED file: every request is exactly what
    was asked, so a read never runs past the end of a device the way a
    buffered reader's read-ahead can."""
    out = bytearray()
    while len(out) < n:
        got = raw.read(n - len(out))
        if not got:
            break
        out += got
    return bytes(out)


def _present(path: str) -> bool:
    """Is the source still attached? Asked when a whole block will not read,
    because on Windows an unplugged drive and a bad sector raise the same
    error number."""
    try:
        if is_windows() and path.startswith("\\\\.\\"):
            return _win_geometry(path) is not None
        return os.path.exists(path)
    except Exception:                                     # noqa: BLE001
        return True                  # cannot tell: carry on, never guess gone


def _read_block(fh, offset: int, n: int, sector: int, retries: int,
                bad: _BadMap, *, base: int = 0, stop=None,
                path: str = "", max_bad_run: int = MAX_BAD_RUN) -> bytes:
    """`n` bytes at `offset` of the source (at `base + offset` of the device
    it is read through). On an error or a short read, sector by sector with
    retries; what still cannot be read is zeros, and goes into `bad`.

    Raises AcquisitionError when the device has gone, or when unreadable
    bytes run on past `max_bad_run`; _Stopped as soon as `stop` is set."""
    raw = getattr(fh, "raw", fh)
    try:
        raw.seek(base + offset)
        data = _read_exact(raw, n)
        if len(data) == n:
            bad.good()
            return data
    except OSError:
        pass
    if path and not _present(path):
        raise AcquisitionError(
            f"The source stopped answering at byte {offset:,} and is no longer "
            "attached — it was unplugged, lost power, or failed outright. "
            "Nothing after this point was read.")
    out = bytearray()
    for pos in range(offset, offset + n, sector):
        if stop is not None and stop.is_set():
            raise _Stopped()
        m = min(sector, offset + n - pos)
        piece = None
        for _attempt in range(retries + 1):
            try:
                raw.seek(base + pos)
                got = _read_exact(raw, m)
            except OSError:
                continue
            if len(got) == m:
                piece = got
                break
        if piece is None:
            bad.add(pos // sector, sector)
            if bad.consecutive_bytes > max_bad_run:
                raise AcquisitionError(
                    f"More than {_human(max_bad_run)} in a row would not read "
                    f"(up to byte {pos:,}). The drive is failing or gone; an "
                    "image of zeros is not evidence. Stop, and image it with a "
                    "tool built for dying drives, or raise the limit.")
            piece = b"\x00" * m
        else:
            bad.good()
        out += piece
    return bytes(out)


def _clock(seconds: float) -> str:
    s = int(max(0, seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {(s % 3600) // 60:02d} min"


def _log_text(result: AcquisitionResult, *, examiner: str, case_text: dict,
              write_blocker: str, case_id: str) -> str:
    src = result.source
    lines = [
        f"Created by ATK Digital Forensics Workshop {__version__} "
        "(forensics_workshop.acquire)",
        "",
        "Case Information:",
        f"Acquired using: ATK Digital Forensics Workshop {__version__}",
        f"Case Number: {case_text.get('case_number', '')}",
        f"Evidence Number: {case_text.get('evidence_number', '')}",
        f"Unique Description: {case_text.get('description', '')}",
        f"Examiner: {examiner}",
        f"Notes: {case_text.get('notes', '')}",
        f"ATK case: {case_id or '(none open)'}",
        "",
        "-" * 62,
        "",
        f"Information for {os.path.join(result.destination, '')}:",
        "",
        "Physical Evidentiary Item (Source) Information:",
        "[Device Info]",
        f" Source: {src.get('path', '')}",
        f" Source Type: {src.get('kind', '')}",
        "[Drive Geometry]",
        f" Bytes per Sector: {src.get('sector_size', '')}",
        f" Sector Count: {(src.get('size') or 0) // (src.get('sector_size') or 512):,}",
        "[Drive Information]",
        f" Vendor: {src.get('vendor', '')}",
        f" Model: {src.get('model', '')}",
        f" Serial Number: {src.get('serial', '')}",
        f" Interface: {src.get('bus', '')}",
        f" Removable: {src.get('removable')}",
        f" Volumes on it: {', '.join(src.get('volumes') or []) or '(none mounted)'}",
        f" Source data size: {src.get('size', 0):,} bytes",
        "[Write protection]",
        f" Hardware write blocker (examiner's words): {write_blocker or '(none stated)'}",
        f" Software: the source was opened read-only. {blocker.HARDWARE_NOTICE}",
        "[Computed Hashes — of the data read]",
        f" MD5 checksum:    {result.hashes.get('md5', '')}",
        f" SHA1 checksum:   {result.hashes.get('sha1', '')}",
        f" SHA256 checksum: {result.hashes.get('sha256', '')}",
        "",
        "Image Information:",
        f" State: {result.state.upper()}"
        + ("" if result.state == "completed" else
           " — THIS IMAGE IS INCOMPLETE AND MUST NOT BE USED AS EVIDENCE"),
        f" Format: {result.fmt.upper()}"
        + (f" (compression {result.compression})" if result.fmt == "e01" else ""),
        f" Acquisition started: {result.started_at}",
        f" Acquisition finished: {result.finished_at}",
        f" Elapsed: {_clock(result.elapsed_s)}",
        f" Bytes read: {result.bytes_read:,} of {src.get('size', 0):,}",
        " Segment list:",
    ]
    for seg in result.segments:
        lines.append(f"  {seg.get('path', '')}  {seg.get('size', 0):,} bytes"
                     + (f"  SHA256 {seg['sha256']}" if seg.get("sha256") else ""))
    lines += ["", "Unreadable sectors (written as zeros):"]
    if result.bad_sectors:
        for first, count in result.bad_sectors:
            lines.append(f"  sector {first:,}" + (f" + {count - 1:,} more"
                                                  if count > 1 else ""))
    else:
        lines.append("  none")
    lines += ["", "Image Verification Results:"]
    v = result.verification or {}
    if result.verified is None:
        lines.append(" Not verified" + (f": {v.get('note')}" if v.get("note") else "."))
    else:
        lines += [
            f" Verification started: {v.get('started_at', '')}",
            f" Verification finished: {v.get('finished_at', '')}",
            f" MD5 checksum:    {v.get('md5', '')} : "
            f"{'verified' if v.get('md5') == result.hashes.get('md5') else 'MISMATCH'}",
            f" SHA1 checksum:   {v.get('sha1', '')} : "
            f"{'verified' if v.get('sha1') == result.hashes.get('sha1') else 'MISMATCH'}",
            f" SHA256 checksum: {v.get('sha256', '')} : "
            f"{'verified' if v.get('sha256') == result.hashes.get('sha256') else 'MISMATCH'}",
        ]
    if result.warnings:
        lines += ["", "Warnings:"] + [f" - {w}" for w in result.warnings]
    if result.error:
        lines += ["", f"Error: {result.error}"]
    return "\n".join(lines) + "\n"


def _abandon(sink) -> list[str]:
    """Close what is open after a stop or a failure — itself unable to fail
    the run a second time (a full disk can make the flush raise again)."""
    try:
        return sink.abandon()
    except Exception:                                     # noqa: BLE001
        return list(getattr(sink, "paths", []))


def acquire(source: str, destination, base_name: str, *, examiner: str,
            fmt: str = "e01", compression: str = "fast",
            segment_bytes: int | None = DEFAULT_SEGMENT, case=None,
            case_number: str = "", evidence_number: str = "",
            description: str = "", notes: str = "", write_blocker: str = "",
            verify: bool = True, retries: int = DEFAULT_RETRIES,
            max_bad_run: int = MAX_BAD_RUN, label: str = "", progress=None,
            stats=None, should_cancel=None) -> AcquisitionResult:
    """Image `source` into `destination` as `base_name`.E01 (or .dd/.001…).

    `progress(str)` gets a sentence every few seconds; `stats(dict)` gets the
    numbers (done, total, rate, eta_s, bad) for a progress bar. With `case`,
    custody records the start and the end, and a completed, verified image
    is registered as evidence. Raises AcquisitionError when the plan is
    refused, Cancelled when stopped (the partial files are left and the log
    says INCOMPLETE)."""
    if not str(examiner or "").strip():
        raise AcquisitionError("Name the examiner: the log and custody say who "
                               "acquired the image.")
    plan = check_plan(source, destination, base_name, fmt=fmt,
                      compression=compression, segment_bytes=segment_bytes,
                      case=case)
    if not plan.ok:
        raise AcquisitionError(" ".join(plan.refusals))
    drive = plan.drive
    say = progress or (lambda _m: None)
    dest = _make_destination(plan.destination)
    base = os.fspath(dest / plan.base_name)
    started_at, t0 = utc_now(), time.monotonic()
    case_text = {"case_number": case_number, "evidence_number": evidence_number,
                 "description": description, "notes": notes}
    if case is not None:
        case.custody.record(
            "acquisition.started", actor=case.actor(), target=plan.destination,
            detail={"source": drive.as_dict(), "format": plan.fmt,
                    "compression": plan.compression,
                    "segment_bytes": plan.segment_bytes,
                    "first_output": plan.first_output(),
                    "write_blocker": write_blocker,
                    "warnings": list(plan.warnings), **case_text})
    if plan.fmt == "e01":
        sink = ewfwrite.EwfWriter(
            base, open_segment=lambda p: _open_output(dest, p),
            size=drive.size, bytes_per_sector=drive.sector_size,
            segment_bytes=plan.segment_bytes, compression=plan.compression,
            media_type=(ewfwrite.MEDIA_REMOVABLE if drive.removable
                        else ewfwrite.MEDIA_FIXED),
            physical=drive.kind == "physical",
            case_text=ewfwrite.CaseText(
                case_number=case_number, evidence_number=evidence_number,
                description=description, examiner=examiner, notes=notes,
                version=f"ATK DFW {__version__}",
                os=f"{platform.system()} {platform.release()}"))
    else:
        sink = _RawSink(dest, base, drive.size, plan.segment_bytes)

    hasher = hashing.Hasher()
    bad = _BadMap()
    state, error, done = "completed", "", 0
    stop = threading.Event()
    blocks: queue.Queue = queue.Queue(maxsize=4)

    def reader():
        """Reads ahead while the main thread hashes and writes."""
        try:
            with blocker.open_evidence(drive.reader) as fh:
                offset = 0
                while offset < drive.size and not stop.is_set():
                    n = min(READ_BLOCK, drive.size - offset)
                    data = _read_block(fh, offset, n, drive.sector_size,
                                       retries, bad, base=drive.read_offset,
                                       stop=stop, path=drive.reader,
                                       max_bad_run=max_bad_run)
                    while not stop.is_set():
                        try:
                            blocks.put((offset, data), timeout=0.5)
                            break
                        except queue.Full:
                            continue
                    offset += n
            blocks.put(None)
        except _Stopped:
            blocks.put(None)
        except BaseException as exc:                      # noqa: BLE001
            blocks.put(exc)

    thread = threading.Thread(target=reader, name="dfw-acquire-read",
                              daemon=True)
    hash_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dfw-hash")
    last_say = 0.0
    try:
        thread.start()
        while True:
            if should_cancel is not None and should_cancel():
                raise Cancelled("acquisition was stopped by the examiner")
            try:
                # A timeout, so Stop is seen within half a second even while
                # the reader is retrying a bad stretch sector by sector.
                item = blocks.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                if stop.is_set() or done < drive.size:
                    if should_cancel is not None and should_cancel():
                        raise Cancelled("acquisition was stopped by the "
                                        "examiner")
                    raise AcquisitionError(f"the reader ended after {done:,} "
                                           "bytes without saying why")
                break
            if isinstance(item, BaseException):
                raise item
            _offset, data = item
            hashed = hash_pool.submit(hasher.update, data)
            sink.write(data)
            hashed.result()
            done += len(data)
            now = time.monotonic()
            if now - last_say >= 2.0 or done == drive.size:
                last_say = now
                rate = done / max(now - t0, 1e-6)
                eta = (drive.size - done) / rate if rate else 0
                bad_n = bad.sectors
                if stats is not None:
                    stats({"done": done, "total": drive.size, "rate": rate,
                           "eta_s": eta, "bad": bad_n})
                say(f"Imaged {_human(done)} of {_human(drive.size)} "
                    f"({rate / 1e6:.0f} MB/s, about {_clock(eta)} left)"
                    + (f" · {bad_n} unreadable sector(s)" if bad_n else ""))
        digest = hasher.result()
        paths = sink.finish(bytes.fromhex(digest.md5), bytes.fromhex(digest.sha1),
                            bad.as_runs())
    except Cancelled as exc:
        state, error = "cancelled", str(exc)
        stop.set()
        paths = _abandon(sink)
    except BaseException as exc:                          # noqa: BLE001
        state, error = "failed", (str(exc) if isinstance(exc, AcquisitionError)
                                  else f"{type(exc).__name__}: {exc}")
        stop.set()
        paths = _abandon(sink)
    finally:
        stop.set()
        while thread.is_alive():          # let the reader see the stop
            try:
                blocks.get(timeout=0.2)
            except queue.Empty:
                pass
        hash_pool.shutdown(wait=True)

    hashes = hasher.result().as_dict() if state == "completed" else {}
    segments = [{"path": p, "size": os.path.getsize(p) if os.path.exists(p)
                 else 0} for p in paths]
    verification: dict = {}
    verified = None
    if state == "completed" and verify:
        say("Verifying: reading the image back and hashing it…")
        v_start = utc_now()
        try:
            with _image.ImageSource.open(paths[0]) as src:
                whole, per_segment = _image.hash_image(
                    src, should_cancel=should_cancel)
            verification = {"started_at": v_start, "finished_at": utc_now(),
                            **whole.as_dict()}
            for seg, h in zip(segments, per_segment):
                seg["sha256"] = h.sha256
            verified = (whole.md5 == hashes["md5"] and whole.sha1 == hashes["sha1"]
                        and whole.sha256 == hashes["sha256"]
                        and whole.size == drive.size)
        except Cancelled:
            verification = {"note": "verification was stopped by the examiner"}
        except Exception as exc:                          # noqa: BLE001
            verified = False
            verification = {"note": f"the image could not be read back: "
                                    f"{type(exc).__name__}: {exc}"}
    elif state == "completed":
        verification = {"note": "verification was switched off"}

    result = AcquisitionResult(
        state=state, source=drive.as_dict(), destination=os.fspath(dest),
        fmt=plan.fmt, compression=plan.compression if plan.fmt == "e01" else "",
        segments=segments, hashes=hashes, bytes_read=done,
        bad_sectors=bad.as_runs(), verified=verified,
        verification=verification, started_at=started_at,
        finished_at=utc_now(), elapsed_s=round(time.monotonic() - t0, 1),
        log=base + ".txt", warnings=list(plan.warnings), error=error)
    omitted = getattr(sink, "error2_omitted", None) or []
    if omitted:
        result.warnings.append(
            f"{len(omitted)} unreadable run(s) lie past sector 2^32, which the "
            "E01's error2 section (32-bit) cannot hold; they are listed in this "
            "log and in custody, not in the E01.")
    log_error = ""
    try:
        _write_log(dest, result.log, _log_text(
            result, examiner=examiner, case_text=case_text,
            write_blocker=write_blocker,
            case_id=case.info.case_id if case is not None else ""))
    except Exception as exc:                              # noqa: BLE001
        # The custody record below still happens: a log that could not be
        # written (a full disk) must not also lose the record of the run.
        log_error = f"{type(exc).__name__}: {exc}"
        result.warnings.append(f"the log could not be written: {log_error}")

    if case is not None:
        detail = {"state": state, "source": drive.as_dict(),
                  "format": plan.fmt, "segments": segments,
                  "bytes_read": done, "verified": verified,
                  "bad_sector_runs": len(result.bad_sectors),
                  "bad_sectors": result.bad_sectors[:CUSTODY_BAD_RUNS],
                  "log": result.log, "elapsed_s": result.elapsed_s,
                  "write_blocker": write_blocker}
        if error:
            detail["error"] = error
        if log_error:
            detail["log_error"] = log_error
        action = {"completed": "acquisition.completed",
                  "cancelled": "acquisition.cancelled"}.get(state,
                                                           "acquisition.failed")
        case.custody.record(action, actor=case.actor(), target=result.log,
                            hashes=hashes, detail=detail)
        if state == "completed" and verified and not log_error:
            item = case.add_image(paths[0], label=label or (
                f"{drive.vendor} {drive.model} {drive.serial}".strip()
                or os.path.basename(paths[0])))
            result.evidence_id = item.id
    if state == "cancelled":
        raise Cancelled(f"{error}. {done:,} bytes were read; the partial image "
                        f"in {dest} is INCOMPLETE and was not registered "
                        f"(log: {result.log}).")
    if state == "completed" and log_error:
        raise AcquisitionError(
            f"The image was written and verified={verified}, but its log could "
            f"not be written ({log_error}), so it was not registered. Custody "
            "records the run.")
    if state == "failed":
        raise AcquisitionError(f"The acquisition failed after {done:,} bytes: "
                               f"{error}. The partial image is INCOMPLETE and "
                               f"was not registered (log: {result.log}).")
    return result
