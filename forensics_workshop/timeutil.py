# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Timestamps: stored raw, decoded beside, never replaced.

Every timestamp this engine reads is a MEASURED value in some epoch and some
unit — WebKit microseconds since 1601, PRTime microseconds since 1970, POSIX
nanoseconds from `stat`. A decoding mistake is the commonest error a
forensic parser makes, and the most damaging, because the decoded value
looks exactly as authoritative as a correct one.

So the rule is structural: **the raw value is kept, and the decoded value
is stored beside it with the name of the epoch that produced it.** A wrong
epoch can then be corrected from the record rather than from the evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

UTC = timezone.utc
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: name -> (epoch, the unit one raw integer counts)
EPOCHS = {
    "webkit_us": (WEBKIT_EPOCH, "microseconds"),   # Chromium, Edge, Brave
    "prtime_us": (UNIX_EPOCH, "microseconds"),     # Firefox places/forms
    "unix_s": (UNIX_EPOCH, "seconds"),
    "unix_ms": (UNIX_EPOCH, "milliseconds"),
    "unix_ns": (UNIX_EPOCH, "nanoseconds"),        # os.stat *_ns
    "filetime": (WEBKIT_EPOCH, "hundred-nanoseconds"),  # NTFS, USN, Win32
}


def iso(dt: datetime) -> str:
    """UTC, microsecond precision, `Z` suffix. One format everywhere."""
    return (dt.astimezone(UTC).isoformat(timespec="microseconds")
            .replace("+00:00", "Z"))


def utc_now() -> str:
    return iso(datetime.now(UTC))


def local_offset() -> str:
    """The examiner machine's UTC offset right now, e.g. `-04:00`.

    Recorded on a case at creation because every "local time" an examiner
    later reads from the case is only interpretable against it.
    """
    offset = datetime.now().astimezone().utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    minutes = abs(minutes)
    return f"{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def decode(raw, epoch: str) -> str | None:
    """Decode one raw timestamp, or None when there is nothing to decode.

    None is returned for NULL, for zero (every format here uses 0 as
    "never set", and decoding it would print 1601 or 1970 as though it had
    happened), for a value that is not an integer, and for a value outside
    the range a `datetime` can hold. It is never guessed at.
    """
    if epoch not in EPOCHS:
        raise ValueError(f"unknown epoch {epoch!r}; known: {sorted(EPOCHS)}")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value == 0:
        return None
    base, unit = EPOCHS[epoch]
    try:
        if unit == "microseconds":
            delta = timedelta(microseconds=value)
        elif unit == "milliseconds":
            delta = timedelta(milliseconds=value)
        elif unit == "nanoseconds":
            delta = timedelta(microseconds=value // 1000)
        elif unit == "hundred-nanoseconds":
            delta = timedelta(microseconds=value // 10)
        else:
            delta = timedelta(seconds=value)
        return iso(base + delta)
    except (OverflowError, ValueError):
        return None


def filetime_fraction(raw) -> int | None:
    """The sub-second part of a FILETIME, in 100-nanosecond ticks (0–9 999 999).

    NTFS keeps 100 ns resolution. A timestamp whose fraction is exactly zero
    was either written by something that works in whole seconds (FAT, a ZIP
    entry, a tool that set it by hand) or lands on a second by chance — one
    in ten million. It is a measurement, recorded so a report can say which
    timestamps are whole seconds; what that means is the examiner's call.
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return value % 10_000_000


def from_ns(ns) -> str | None:
    """A `stat` nanosecond value, decoded. Zero is a real value here."""
    if ns is None:
        return None
    try:
        return iso(UNIX_EPOCH + timedelta(microseconds=int(ns) // 1000))
    except (OverflowError, ValueError, TypeError):
        return None


def infer_unix_unit(raw) -> str | None:
    """For a column whose unit changed between versions of the software
    that wrote it. Returns `unix_s` or `unix_ms`, or None.

    This is an INFERENCE and every caller records it as one: the value is
    read as milliseconds when it is too large to be a plausible count of
    seconds (beyond the year 5138), and as seconds otherwise.
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return "unix_ms" if value > 100_000_000_000 else "unix_s"
