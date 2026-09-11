# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The read-only ratchet: a write anywhere but a listed writer fails the build.

**WHY THIS IS AN AST WALK AND NOT A SEARCH FOR `"w"`.** ATK has learned this
four times in one afternoon: a text search for a forbidden string matches the
COMMENT explaining why it is forbidden, and misses the call spelled a
different way. This walks the syntax tree and looks at what the code
EXECUTES — the callee, the mode argument, the flag names — so a docstring
that says `open(path, "w")` is not a violation and `Path(p).write_bytes(b)`
is.

What counts as a write, anywhere in the package:

* `open`/`io.open`/`codecs.open`/`os.fdopen`/`gzip.open`/`bz2.open`/
  `lzma.open`/`tarfile.open`/`zipfile.ZipFile`/`Path.open` with a mode
  containing `w`, `a`, `x` or `+` — and a mode that is not a literal, since
  a mode nobody can read cannot be proven read-only;
* `os.open` with any of `O_WRONLY`, `O_RDWR`, `O_APPEND`, `O_CREAT`,
  `O_TRUNC`, `O_EXCL` — including through a module constant, which is
  followed back to its definition — and with any flag it cannot identify;
* every call that creates, renames, copies, truncates, re-times or deletes:
  `os.remove`, `shutil.copy2`, `Path.write_bytes`, `Path.mkdir`, …;
* `sqlite3.connect`, because opening a database can write to it;
* registry writes, and the Win32 calls that open or alter files directly
  (`CreateFileW`, `WriteFile`, `SetFileTime`, `DeviceIoControl` …).

Each site must sit inside a function named in `blocker.WRITERS`, and a
`case` writer must call `assert_case_path` in its own body. A WRITERS entry
that matches no function is a failure too.

**AND IT REPORTS WHAT IT LOOKED AT.** A guard that quietly stops inspecting
anything turns green and stays green — ATK ran a wiring checker for five days
that was examining 11 of 87 classes. `Report.files`, `functions` and
`opens_inspected` exist so the test can assert the net actually covers the
package, and `scan_source` exists so the test can watch it fail.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT",
                         "O_TRUNC", "O_EXCL", "O_TEMPORARY", "O_SHORT_LIVED"})
READ_FLAGS = frozenset({"O_RDONLY", "O_BINARY", "O_NOATIME", "O_NOINHERIT",
                        "O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY",
                        "O_SEQUENTIAL", "O_RANDOM"})

#: (module, function) pairs that mutate the file system or the registry.
MUTATORS = frozenset({
    ("os", n) for n in (
        "remove", "unlink", "rmdir", "removedirs", "rename", "renames",
        "replace", "mkdir", "makedirs", "truncate", "ftruncate", "utime",
        "chmod", "lchmod", "chown", "lchown", "link", "symlink", "write",
        "pwrite", "writev", "mkfifo", "mknod", "chflags", "lchflags",
        "setxattr", "removexattr")
} | {
    ("shutil", n) for n in (
        "rmtree", "move", "copy", "copy2", "copyfile", "copytree",
        "copymode", "copystat", "chown")
} | {
    ("tempfile", n) for n in (
        "mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryFile",
        "SpooledTemporaryFile", "TemporaryDirectory")
} | {
    ("winreg", n) for n in (
        "SetValue", "SetValueEx", "CreateKey", "CreateKeyEx", "DeleteKey",
        "DeleteKeyEx", "DeleteValue", "SaveKey", "LoadKey")
} | {("sqlite3", "connect"), ("mmap", "mmap")})

#: Methods that mutate whatever object they are called on (Path, file).
MUTATOR_METHODS = frozenset({"write_text", "write_bytes", "unlink", "touch",
                             "mkdir", "rmdir", "chmod", "lchmod",
                             "symlink_to", "hardlink_to", "link_to",
                             "truncate"})

#: `str.replace(a, b)` is everywhere; `Path.replace(target)` takes ONE
#: argument. One positional and no keywords is read as the Path method.
ONE_ARG_METHODS = frozenset({"rename", "replace"})

#: Win32 entry points that open or alter files beneath Python's own `open`.
WIN32_WRITERS = frozenset({"CreateFileW", "CreateFileA", "WriteFile",
                           "SetFileTime", "DeviceIoControl", "DeleteFileW",
                           "DeleteFileA", "MoveFileExW", "MoveFileW",
                           "SetFileAttributesW", "SetEndOfFile",
                           "SetFileInformationByHandle"})

#: opener -> (index of the mode argument, default mode)
OPENERS = {
    ("", "open"): (1, "r"), ("io", "open"): (1, "r"),
    ("codecs", "open"): (1, "r"), ("os", "fdopen"): (1, "r"),
    ("gzip", "open"): (1, "rb"), ("bz2", "open"): (1, "rb"),
    ("lzma", "open"): (1, "rb"), ("tarfile", "open"): (1, "r"),
    ("zipfile", "ZipFile"): (1, "r"), ("gzip", "GzipFile"): (1, "rb"),
}


@dataclass
class Site:
    qualname: str
    lineno: int
    what: str
    allowed: bool = False


@dataclass
class Report:
    files: list = field(default_factory=list)
    functions: int = 0
    opens_inspected: int = 0
    sites: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    writers_seen: set = field(default_factory=set)
    stale_writers: set = field(default_factory=set)

    @property
    def ok(self) -> bool:
        return not self.violations


def _is_write_mode(mode: str) -> bool:
    return any(ch in mode for ch in "wax+")


class _Scanner(ast.NodeVisitor):
    def __init__(self, module: str, tree: ast.Module, writers: dict,
                 report: Report) -> None:
        self.module = module
        self.writers = writers
        self.report = report
        self.stack: list[str] = []
        self.funcs: list[ast.AST] = []
        self.aliases: dict[str, tuple[str, str]] = {}   # local -> (module, name)
        self.modules: dict[str, str] = {}               # local -> module
        self.constants: dict[str, ast.AST] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.constants[t.id] = node.value

    # -- names ------------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            if a.asname:
                self.modules[a.asname] = a.name
            else:                       # `import os.path` binds `os`
                top = a.name.split(".")[0]
                self.modules[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name] = (node.module or "", a.name)
        self.generic_visit(node)

    def _callee(self, func) -> tuple[str, str] | None:
        """(module, name) for `mod.name(...)` or an imported `name(...)`."""
        if isinstance(func, ast.Name):
            if func.id in self.aliases:
                return self.aliases[func.id]
            return "", func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            if base in self.modules:
                return self.modules[base], func.attr
        return None

    # -- scopes -----------------------------------------------------------
    def _qualname(self) -> str:
        return f"{self.module}:{'.'.join(self.stack)}" if self.stack \
            else f"{self.module}:<module>"

    def visit_ClassDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def _visit_function(self, node):
        self.report.functions += 1
        self.stack.append(node.name)
        self.funcs.append(node)
        qual = self._qualname()
        if qual in self.writers:
            self.report.writers_seen.add(qual)
            self._check_writer_shape(qual, node)
        self.generic_visit(node)
        self.funcs.pop()
        self.stack.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _enclosing_writer(self) -> str | None:
        """The innermost enclosing function that is a listed writer."""
        for depth in range(len(self.stack), 0, -1):
            qual = f"{self.module}:{'.'.join(self.stack[:depth])}"
            if qual in self.writers:
                return qual
        return None

    def _check_writer_shape(self, qual: str, node) -> None:
        kind = self.writers[qual]
        if kind == "case":
            called = {getattr(n.func, "attr", getattr(n.func, "id", ""))
                      for n in ast.walk(node) if isinstance(n, ast.Call)}
            if "assert_case_path" not in called:
                self.report.violations.append(
                    f"{qual} (line {node.lineno}) is a CASE writer that "
                    "never calls assert_case_path — nothing stops it being "
                    "handed an evidence path")
        elif kind == "probe":
            kwonly = {a.arg: d for a, d in zip(node.args.kwonlyargs,
                                               node.args.kw_defaults)}
            if "confirm_not_evidence" not in kwonly or \
                    kwonly["confirm_not_evidence"] is not None:
                self.report.violations.append(
                    f"{qual} is the write PROBE and must take "
                    "confirm_not_evidence as a keyword-only argument with "
                    "no default")

    # -- the checks -------------------------------------------------------
    def _site(self, node, what: str) -> None:
        writer = self._enclosing_writer()
        site = Site(self._qualname(), node.lineno, what, writer is not None)
        self.report.sites.append(site)
        if writer is None:
            self.report.violations.append(
                f"{site.qualname} line {node.lineno}: {what} — not inside "
                "any function listed in blocker.WRITERS")

    def _flag_names(self, expr, seen=None) -> tuple[set, set]:
        """(flag names, unidentified names) in an os.open flags expression."""
        seen = set() if seen is None else seen
        flags, unknown = set(), set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Attribute) and n.attr.startswith("O_"):
                flags.add(n.attr)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) \
                    and n.value.startswith("O_"):
                flags.add(n.value)
            elif isinstance(n, ast.Name) and n.id not in ("os", "getattr"):
                if n.id.startswith("O_"):
                    flags.add(n.id)
                elif n.id in self.constants and n.id not in seen:
                    seen.add(n.id)
                    f, u = self._flag_names(self.constants[n.id], seen)
                    flags |= f
                    unknown |= u
                elif n.id not in seen:
                    unknown.add(n.id)
        return flags, unknown

    def visit_Call(self, node):
        callee = self._callee(node.func)
        func = node.func

        # openers with a mode
        opener = OPENERS.get(callee) if callee else None
        if opener is None and callee and callee[0] == "" and callee[1] == "open":
            opener = OPENERS[("", "open")]
        if opener is not None:
            self.report.opens_inspected += 1
            self._check_mode(node, *opener, label=f"{'.'.join(p for p in callee if p)}()")
        elif isinstance(func, ast.Attribute) and func.attr == "open" and \
                not (callee and callee[0]):
            # `Path(p).open("wb")` — but also `zipfile.ZipFile.open(name)`,
            # whose first argument is an entry name. A keyword mode is always
            # checked; a positional one only when it is a literal that reads
            # as a mode, so an entry name is not mistaken for one.
            self.report.opens_inspected += 1
            first = node.args[0] if node.args else None
            looks_like_mode = (isinstance(first, ast.Constant)
                               and isinstance(first.value, str)
                               and 0 < len(first.value) <= 4
                               and set(first.value) <= set("rwxabtU+"))
            if any(kw.arg == "mode" for kw in node.keywords) or looks_like_mode:
                self._check_mode(node, 0, "r", label=".open()")

        if callee == ("os", "open"):
            self.report.opens_inspected += 1
            if len(node.args) < 2:
                self._site(node, "os.open() with no readable flags")
            else:
                flags, unknown = self._flag_names(node.args[1])
                bad = flags & WRITE_FLAGS
                odd = (flags - WRITE_FLAGS - READ_FLAGS) | unknown
                if bad:
                    self._site(node, f"os.open() with {sorted(bad)}")
                elif odd:
                    self._site(node, f"os.open() with unidentified flags "
                                     f"{sorted(odd)}")

        if callee and callee in MUTATORS:
            if callee == ("mmap", "mmap") and any(
                    kw.arg == "access" and getattr(kw.value, "attr", "") ==
                    "ACCESS_READ" for kw in node.keywords):
                pass
            else:
                self._site(node, f"{callee[0]}.{callee[1]}()")
        elif isinstance(func, ast.Attribute):
            if func.attr in MUTATOR_METHODS and not (callee and callee[0]):
                self._site(node, f".{func.attr}()")
            elif (func.attr in ONE_ARG_METHODS and len(node.args) == 1
                  and not node.keywords and not (callee and callee[0])):
                self._site(node, f".{func.attr}() (read as Path.{func.attr})")
            if func.attr in WIN32_WRITERS:
                self._site(node, f"Win32 {func.attr}()")
        self.generic_visit(node)

    def _check_mode(self, node, index: int, default: str, label: str) -> None:
        mode_node = None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode_node = kw.value
        if mode_node is None and len(node.args) > index:
            mode_node = node.args[index]
        if mode_node is None:
            mode = default
        elif isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
            mode = mode_node.value
        else:
            self._site(node, f"{label} with a mode that is not a literal")
            return
        if _is_write_mode(mode):
            self._site(node, f"{label} mode {mode!r}")


def scan_source(source: str, module: str, writers: dict | None = None,
                report: Report | None = None) -> Report:
    report = report if report is not None else Report()
    tree = ast.parse(source)
    _Scanner(module, tree, writers or {}, report).visit(tree)
    return report


def scan_package(package_dir, writers: dict) -> Report:
    """Scan every .py file under `package_dir`, module names relative to it."""
    root = Path(package_dir)
    report = Report()
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).with_suffix("")
        parts = [p for p in rel.parts if p != "__init__"]
        module = ".".join(parts) or "__init__"
        report.files.append(module)
        scan_source(path.read_text(encoding="utf-8"), module, writers, report)
    report.stale_writers = set(writers) - report.writers_seen
    for stale in sorted(report.stale_writers):
        report.violations.append(
            f"blocker.WRITERS names {stale}, which does not exist — a list "
            "of writers that no longer describes the code is not a guard")
    return report
