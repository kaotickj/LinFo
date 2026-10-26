#!/usr/bin/env python3
"""Build LinFo's dependency-based Debian package without installing anything."""
from __future__ import annotations
import argparse
import ast
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def version() -> str:
    tree = ast.parse((ROOT / "src/linfo/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError("LinFo version is missing")


def write(root: Path, name: str, text: str, mode: int = 0o644):
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    target.chmod(mode)


def build(output: Path) -> Path:
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("dpkg-deb is required to build a Debian package")
    release = re.sub(r"(a|b|rc)(\d+)$", r"~\1\2", version())
    output.mkdir(parents=True, exist_ok=True)
    destination = output.resolve() / f"linfo_{release}_all.deb"
    with tempfile.TemporaryDirectory(prefix="linfo-deb-") as temporary:
        staging = Path(temporary) / "linfo"
        application = staging / "usr/share/linfo"
        shutil.copytree(ROOT / "src/linfo", application / "src/linfo", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for relative in ("privileged/linfo-helper", "scripts/install-helper.sh", "LinFo.png"):
            target = application / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
            target.chmod(0o755 if relative != "LinFo.png" else 0o644)
        for document in ("README.md", "CHANGELOG.md", "LICENSE"):
            target = staging / "usr/share/doc/linfo" / document
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / document, target)
        write(staging, "usr/bin/linfo", '''#!/usr/bin/python3 -I
import sys
sys.path.insert(0, "/usr/share/linfo/src")
from linfo.__main__ import main
raise SystemExit(main())
''', 0o755)
        write(staging, "usr/share/applications/linfo.desktop", '''[Desktop Entry]
Type=Application
Name=LinFo
GenericName=Linux Security Assessment
Comment=Inspect Linux hardware, security controls, and hardening
Exec=linfo
Icon=linfo
Terminal=false
Categories=System;Security;
Keywords=Linux;Security;Audit;Hardening;
StartupNotify=true
''')
        icon = staging / "usr/share/pixmaps/linfo.png"
        icon.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "LinFo.png", icon)
        installed_size = (sum(path.stat().st_size for path in staging.rglob("*") if path.is_file()) + 1023) // 1024
        write(staging, "DEBIAN/control", f'''Package: linfo
Version: {release}
Section: admin
Priority: optional
Architecture: all
Maintainer: Kaotick Jay <kaotickj@users.noreply.github.com>
Depends: python3 (>= 3.10), python3-pyqt6 (>= 6.5)
Recommends: iproute2, pciutils, procps
Installed-Size: {installed_size}
Homepage: https://github.com/kaotickj/LinFo
Description: Linux inventory, local assessment, and guided hardening
 PyQt6 desktop with cancellable local inspections, evidence review, reports,
 and existing allowlisted administration controls. The optional PolicyKit
 helper is supplied as source and is not activated by package installation.
''')
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(staging), str(destination)], check=True)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix + ".sha256").write_text(f"{digest}  {destination.name}\n", encoding="utf-8")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    arguments = parser.parse_args()
    print(build(arguments.output))
