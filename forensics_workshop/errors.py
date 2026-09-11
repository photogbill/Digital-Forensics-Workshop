# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Every exception the engine raises on purpose.

One base class so a host can catch "the engine refused" without catching
programming errors, and one subclass per refusal so the message and the
remedy can differ. A refusal is not a crash: each of these carries a
sentence the operator can act on.
"""

from __future__ import annotations


class ForensicsError(Exception):
    """Base for every deliberate refusal in the engine."""


class Cancelled(ForensicsError):
    """The operator asked a long job to stop, and it did."""


class CaseError(ForensicsError):
    """A case folder is not usable as asked."""


class CaseLayoutError(CaseError):
    """The case and the evidence overlap.

    A case folder inside the evidence would be hashed as evidence, and every
    write the case makes would land inside the evidence. Evidence inside the
    case folder would be treated as case data. Both are refused outright.
    """


class CasePathError(CaseError):
    """A write inside the case was pointed somewhere outside it."""


class EvidenceError(ForensicsError):
    """An evidence source is missing, unreadable, or already registered."""


class CustodyRefused(ForensicsError):
    """Something that may not write to the custody log tried to.

    The log records actions and who took them. A model is not an actor that
    can take a custodial action, and a custody record never states a
    conclusion; both are refused here rather than trusted to a caller.
    """


class CustodyError(ForensicsError):
    """The custody log could not be read or appended to."""


class FileSystemError(ForensicsError):
    """A disk or file system structure could not be read as asked.

    Raised for what cannot be read at all — a boot sector that is not one, a
    record outside the MFT, a stream whose content is compressed or encrypted
    and would be returned as garbage. Damage that CAN be read around is not
    raised: it is reported beside the result, because a damaged record is
    itself evidence.
    """
