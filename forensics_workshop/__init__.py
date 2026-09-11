# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The Digital Forensics Workshop engine.

Evidence handling for ATK, standing alone: a case store, an append-only
custody log, hashing, read-only access to evidence, a logical folder walk,
signature-based type identification, browser artefacts — and, from Phase 2,
disk images: RAW/DD and split images, MBR and GPT, NTFS records with deleted
entries and timestamp indicators, the change journal, file slack, and
signature carving with preview.

**THIS FILE IMPORTS NOTHING, AND THAT IS A DECISION, NOT AN OVERSIGHT.**
ATK's airlock (`atk/ui/subsystem.py`) decides "is the engine installed" by
doing exactly one thing: `import forensics_workshop`. If this file pulled in
`case`, a SyntaxError in `case.py` would make that import fail, and ATK would
report a missing engine that is sitting right there on disk — the
2026-09-04 CyberWolf misdiagnosis, rebuilt in a new repository. So the
package imports cleanly whenever it is present, and a defect in any module
surfaces where the operator can read it: past the probe, with a file and a
line. `tests/test_isolation.py` holds this file to it.

The same test holds the rest of the package to three more rules: nothing
here imports ATK, nothing imports Qt, and nothing imports a third-party
package. The engine is standard library only, which is what makes it runnable
and testable in a bare interpreter — and what keeps it inside Bill's licence
rule, nothing that restricts commercial use (FORENSICS_PLAN.md §1.1).
"""

__version__ = "0.2.0"

#: Which phase of FORENSICS_PLAN.md this tree implements.
PHASE = 2

#: The importable name, and where it comes from. The PACKAGE is what ATK
#: probes; the repository is only ever named. Probing the repository name
#: is the mistake the Writing Workshop made first.
PACKAGE = "forensics_workshop"
REPOSITORY = "github.com/photogbill/Digital-Forensics-Workshop"
