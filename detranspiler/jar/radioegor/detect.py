from pathlib import Path

RADIOEGOR_MARKERS = ('native0.Loader', 'native0/Loader', 'native0.hidden.Hidden0', 'registerNativesForClass', 'special_clinit_')

def _is_radioegor_native_obfuscator(jar_sources_dir: Path) -> bool:
    for java_file in sorted(jar_sources_dir.rglob('*.java'))[:2000]:
        try:
            text = java_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        if sum((1 for marker in RADIOEGOR_MARKERS if marker in text)) >= 2:
            return True
    return False
