from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SESSION = os.environ.get("DETRANSPILER_SMOKE_SESSION")


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    msg = f"  [{status}] {name}"
    if detail:
        msg += f" - {detail}"
    print(msg)
    if not ok:
        raise SystemExit(1)


def main() -> int:
    print("smoke test")
    sys.path.insert(0, str(ROOT))

    from detranspiler.jar.radioegor import build_radioegor_overlay_sources
    from detranspiler.jar.final_sources import build_final_sources
    from detranspiler.recovery.metrics import build_recovery_summary
    from detranspiler.reporting.native_map import build_native_map
    from detranspiler.reporting.re_map import write_re_map_from_job
    from detranspiler.gui.views.sources import build_sources_tree
    from detranspiler.gui.views.native_map import build_native_map_tree
    from detranspiler.jar.scan import _jar_scan_classes

    check("imports", True)

    if not SESSION or not Path(SESSION).is_dir():
        print("  [SKIP] set DETRANSPILER_SMOKE_SESSION to an analyzed output folder")
        return 0

    session = Path(SESSION)
    job = json.loads((session / "job.json").read_text(encoding="utf-8"))
    pseudocode_dir = session / "pseudocode"
    analysis_dir = session / "analysis"

    native_index = json.loads((analysis_dir / "native_index.json").read_text(encoding="utf-8"))
    jni_register = (
        json.loads((analysis_dir / "jni_register.json").read_text(encoding="utf-8"))
        if (analysis_dir / "jni_register.json").is_file()
        else None
    )

    radio = build_radioegor_overlay_sources(pseudocode_dir=pseudocode_dir, native_index=native_index)
    check("radioegor overlay", radio.get("status") == "OK", str(radio.get("methods_overlaid")))
    check("radioegor files", int(radio.get("files_written") or 0) > 0, str(radio.get("files_written")))
    check("radioegor records", int(radio.get("records_canonicalized") or 0) >= 0, str(radio.get("records_canonicalized")))

    final = build_final_sources(pseudocode_dir=pseudocode_dir)
    check("final sources", final.get("status") == "OK", str(final.get("files_total")))

    recovery = build_recovery_summary(job=job)
    check("recovery status", recovery.get("status") == "OK")
    recovered = int(recovery.get("native_methods_recovered") or 0)
    total = int(recovery.get("native_methods_total") or 0)
    check("recovery count", recovered > 0 and total > 0, f"{recovered}/{total}")
    check("recovery pct", float(recovery.get("recovery_rate") or 0) > 0)
    app_classes = sum(1 for c in (recovery.get("classes") or []) if c.get("is_application_class"))
    check("recovery app classes", app_classes > 0, str(app_classes))

    tree = build_sources_tree(pseudocode_dir=pseudocode_dir)
    check("sources tree", tree.get("status") == "OK" and tree.get("entries_total", 0) > 0, str(tree.get("entries_total")))

    nm_tree = build_native_map_tree(out_dir=session)
    check("native map tree", nm_tree.get("status") == "OK")

    re_map = write_re_map_from_job(
        job=job,
        analysis_dir=analysis_dir,
        out_html=analysis_dir / "_smoke_re_map.html",
        out_json=analysis_dir / "_smoke_re_map.json",
    )
    check("re_map", re_map.get("status") == "OK")

    pseudo_c = session / "pseudo_c" / "decompiled.c"
    functions_json = session / "ghidra" / "functions.json"
    if pseudo_c.is_file() and functions_json.is_file():
        nm = build_native_map(
            out_dir=session / "_smoke_native_map",
            pseudo_c_path=pseudo_c,
            functions_json_path=functions_json,
            native_index=native_index,
            jni_register=jni_register,
            binary_name="native",
        )
        check("native_map build", nm.get("status") == "OK", str(nm.get("methods_total")))

    jar_path = job.get("input", {}).get("jar_path") or job.get("artifacts", {}).get("jar_path")
    if isinstance(jar_path, str) and Path(jar_path).is_file():
        scan = _jar_scan_classes(Path(jar_path))
        check("jar scan", isinstance(scan, dict) and scan.get("classes"))

    print("all checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
