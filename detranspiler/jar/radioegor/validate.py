import re
from typing import List, Optional

from detranspiler.java.body.recovery import is_invalid_java_body_lines, is_stub_body_lines
from detranspiler.jar.radioegor.util import _NATIVE_JUNK_RE

_RADIOEGOR_GARBAGE_RE = re.compile('0x[0-9a-fA-F]*[fF]{10,}[0-9a-fA-F]*|(?<![\\w.])(?:\\(\\s*\\)\\s*;?)|(?<![\\w.])\\(\\s*[&|^%/<>=]|=\\s*0x[0-9a-fA-F]{9,}\\s*;')

def _radioegor_line_is_low_value(line: str) -> bool:
    ln = line.strip()
    if re.match('^final\\s+String\\s+_s\\d+\\s*=', ln):
        return True
    if re.match('^(?:final\\s+)?[A-Za-z_][\\w<>\\[\\].]*\\s+v\\d+\\s*=\\s*[^;]+;$', ln):
        return True
    return False

def _radioegor_body_is_usable(body: List[str]) -> bool:
    if is_stub_body_lines(body) or is_invalid_java_body_lines(body):
        return False
    meaningful = [ln.strip() for ln in body if ln.strip() and not ln.strip().startswith('//')]
    if not meaningful:
        return False
    if any(_NATIVE_JUNK_RE.search(ln) for ln in meaningful):
        return False
    if any(_RADIOEGOR_GARBAGE_RE.search(ln) for ln in meaningful):
        return False
    if any('classloader == null' in ln or ' npe' in ln for ln in meaningful):
        return False
    if any(re.match('return\\s+[()]+;', ln) for ln in meaningful):
        return False
    non_control = [ln for ln in meaningful if not re.match('^(?:for|if|while|switch)\\s*\\(', ln)]
    if any(re.search('\\(\\s*[&|^*/%+<>=-]|[&|^*/%+<>=-]\\s*\\)', ln) for ln in non_control):
        return False
    if all(_radioegor_line_is_low_value(ln) for ln in meaningful):
        return False
    return True

def _meaningful_count(body: Optional[List[str]]) -> int:
    if not isinstance(body, list):
        return 0
    return sum(1 for ln in body if isinstance(ln, str) and ln.strip() and not ln.strip().startswith('//'))
