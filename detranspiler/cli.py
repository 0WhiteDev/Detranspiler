import argparse
import os
from pathlib import Path
from detranspiler.pipeline.runner import run_pipeline

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='detranspiler')
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('analyze')
    a.add_argument('input', help='Path to DLL/SO/DYLIB')
    a.add_argument('--out', required=True, help='Output directory')
    a.add_argument('--mode', default='AUTO', choices=['AUTO', 'MANAGED', 'JNI', 'AOT', 'GENERIC_NATIVE'])
    a.add_argument('--no-ghidra', action='store_true')
    a.add_argument('--ghidra-install-dir', default=None)
    a.add_argument('--pseudo-c', default=None, help='Optional path to an existing Ghidra decompiled.c')
    a.add_argument('--functions-json', default=None, help='Optional path to an existing Ghidra functions.json')
    a.add_argument('--strings-json', default=None, help='Optional path to an existing Ghidra strings.json')
    a.add_argument('--jar', default=None, help='Optional path to a JAR to recover class/method modifiers')
    a.add_argument('--no-jar-decompile', action='store_true', help='Skip CFR decompilation of --jar')
    a.add_argument('--no-java-validation', action='store_true', help='Skip Java AST validation and safe repairs')
    a.add_argument('--javac-validation', action='store_true', help='Optionally compile recovered Java in an isolated javac invocation')
    a.add_argument('--force', action='store_true')
    e = sub.add_parser('extract', help='Safely extract a native library from a JAR')
    e.add_argument('--jar', required=True, help='Input JAR path')
    e.add_argument('--out', required=True, help='Output directory')
    e.add_argument('--mode', required=True, choices=['standard', 'jnic'])
    d = sub.add_parser('doctor')
    d.add_argument('--ghidra-install-dir', default=None)
    d.add_argument('--json', action='store_true')
    s = sub.add_parser('summarize')
    s.add_argument('job', nargs='?', default=None, help='Path to job.json (default: ./job.json)')
    s.add_argument('--out', default=None, help='Write summary to file')
    m = sub.add_parser('re-map')
    m.add_argument('job', nargs='?', default=None, help='Path to job.json (optional with --demo)')
    m.add_argument('--demo', action='store_true', help='Write sample RE map to examples/')
    m.add_argument('--out', default=None, help='Output HTML path (default: analysis/re_map.html or examples/re_map_demo.html)')
    m.add_argument('--max-nodes', type=int, default=400, help='Maximum graph nodes')
    g = sub.add_parser('gui', help='Launch desktop GUI (requires pywebview)')
    g.add_argument('--width', type=int, default=None)
    g.add_argument('--height', type=int, default=None)
    f = sub.add_parser('diff', help='Compare two native binaries or completed analyses')
    f.add_argument('old', help='Old native binary, analysis directory, or job.json')
    f.add_argument('new', help='New native binary, analysis directory, or job.json')
    f.add_argument('--out', default=None, help='Output directory')
    f.add_argument('--old-jar', default=None, help='Optional companion JAR for the old binary')
    f.add_argument('--new-jar', default=None, help='Optional companion JAR for the new binary')
    f.add_argument('--mode', default='AUTO', choices=['AUTO', 'MANAGED', 'JNI', 'AOT', 'GENERIC_NATIVE'])
    f.add_argument('--no-ghidra', action='store_true')
    f.add_argument('--ghidra-install-dir', default=None)
    f.add_argument('--no-jar-decompile', action='store_true')
    f.add_argument('--no-java-validation', action='store_true')
    f.add_argument('--force', action='store_true')
    return p

def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == 'analyze':
        in_path = Path(args.input)
        out_dir = Path(args.out)
        ghidra_install_dir = args.ghidra_install_dir
        if ghidra_install_dir is None:
            ghidra_install_dir = os.environ.get('GHIDRA_INSTALL_DIR')
        job = run_pipeline(input_path=in_path, out_dir=out_dir, requested_mode=args.mode, use_ghidra=not args.no_ghidra, ghidra_install_dir=Path(ghidra_install_dir) if ghidra_install_dir else None, external_pseudo_c_path=Path(args.pseudo_c) if args.pseudo_c else None, external_functions_json_path=Path(args.functions_json) if args.functions_json else None, external_strings_json_path=Path(args.strings_json) if args.strings_json else None, jar_path=Path(args.jar) if args.jar else None, force=args.force, decompile_jar=not args.no_jar_decompile, validate_java=not args.no_java_validation, compile_java=args.javac_validation)
        analysis = job.get('analysis') if isinstance(job.get('analysis'), dict) else {}
        failures = []
        for key in ('java_like', 'jni_register', 'jni_calls', 'java_validation', 'report'):
            item = analysis.get(key)
            if isinstance(item, dict) and item.get('status') == 'EXCEPTION':
                failures.append(key)
        ghidra_run = job.get('ghidra', {}).get('run') if isinstance(job.get('ghidra'), dict) else None
        if isinstance(ghidra_run, dict) and ghidra_run.get('status') == 'EXCEPTION':
            failures.append('ghidra')
        return 1 if failures else 0
    if args.command == 'extract':
        import json
        from detranspiler.extract import ExtractionError, extract_native_library
        try:
            result = extract_native_library(
                jar_path=Path(args.jar),
                out_dir=Path(args.out),
                mode=args.mode,
            )
        except ExtractionError as exc:
            print(f'ERROR [{exc.code}]: {exc}')
            return 1
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    if args.command == 'doctor':
        from detranspiler.doctor import run_doctor
        ghidra_install_dir = args.ghidra_install_dir
        if ghidra_install_dir is None:
            ghidra_install_dir = os.environ.get('GHIDRA_INSTALL_DIR')
        return run_doctor(ghidra_install_dir=Path(ghidra_install_dir) if ghidra_install_dir else None, as_json=bool(args.json))
    if args.command == 'summarize':
        from detranspiler.reporting.summarize import summarize_job_file
        job_path = Path(args.job) if args.job else Path('job.json')
        text = summarize_job_file(job_path)
        if args.out:
            Path(args.out).write_text(text + '\n', encoding='utf-8')
        else:
            print(text)
        return 0
    if args.command == 're-map':
        from detranspiler.reporting.graph_model import build_demo_re_graph
        from detranspiler.reporting.re_map import get_analysis_dir_from_job, write_re_map_from_job, write_re_map_html
        if args.demo:
            out_html = Path(args.out) if args.out else Path('examples') / 're_map_demo.html'
            res = write_re_map_html(graph=build_demo_re_graph(), out_path=out_html, json_path=out_html.with_suffix('.json'))
            print(res.get('output_path') or res)
            return 0 if res.get('status') == 'OK' else 1
        job_path = Path(args.job) if args.job else Path('job.json')
        if not job_path.is_file():
            print(f'job.json not found: {job_path}')
            return 1
        import json
        job = json.loads(job_path.read_text(encoding='utf-8'))
        analysis_dir = get_analysis_dir_from_job(job)
        if analysis_dir is None or not analysis_dir.is_dir():
            print('Could not resolve analysis directory from job.json')
            return 1
        out_html = Path(args.out) if args.out else analysis_dir / 're_map.html'
        res = write_re_map_from_job(job=job, analysis_dir=analysis_dir, out_html=out_html, out_json=out_html.with_suffix('.json'), max_nodes=args.max_nodes)
        print(res.get('output_path') or res.get('status'))
        return 0 if res.get('status') == 'OK' else 1
    if args.command == 'gui':
        from detranspiler.gui.app import launch_gui
        return launch_gui(width=args.width, height=args.height)
    if args.command == 'diff':
        from detranspiler.diffing import run_diff
        from detranspiler.diffing.session import DiffError
        old_path = Path(args.old)
        new_path = Path(args.new)
        out_dir = Path(args.out) if args.out else Path(f'diff-{old_path.stem}-to-{new_path.stem}')
        ghidra_install_dir = args.ghidra_install_dir or os.environ.get('GHIDRA_INSTALL_DIR')
        try:
            result = run_diff(
                old_path=old_path,
                new_path=new_path,
                out_dir=out_dir,
                old_jar=Path(args.old_jar) if args.old_jar else None,
                new_jar=Path(args.new_jar) if args.new_jar else None,
                mode=args.mode,
                use_ghidra=not args.no_ghidra,
                ghidra_install_dir=Path(ghidra_install_dir) if ghidra_install_dir else None,
                decompile_jar=not args.no_jar_decompile,
                validate_java=not args.no_java_validation,
                force=args.force,
            )
        except (DiffError, FileNotFoundError, FileExistsError, ValueError) as exc:
            print(f'ERROR: {exc}')
            return 1
        print(result['artifacts']['text'])
        print(result['artifacts']['html'])
        print(result['artifacts']['json'])
        return 0
    raise SystemExit(2)
if __name__ == '__main__':
    raise SystemExit(main())
