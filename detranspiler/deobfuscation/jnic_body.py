from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from detranspiler.deobfuscation.jnic_patterns.method_handles import recover_method_handle_resolver
from detranspiler.deobfuscation.jnic_patterns.string_concat import find_string_concat_lowerings, render_string_concat
from detranspiler.java.jni_descriptors import _jni_method_sig_to_java
_ARG_INDEX_RE = re.compile('\\(\\*\\*\\(code\\s*\\*\\*\\)\\(\\*\\s*\\w+\\s*\\+\\s*0x568\\)\\)\\s*\\(\\s*\\w+\\s*,\\s*(?P<args>\\w+)\\s*,\\s*(?P<idx>\\d+)\\s*\\)')
_RETURN_RE = re.compile(r'return\s+(?P<expr>[\w.\[\]+\-*/^&|<>!=, ]+);')
_PARAM_ALIAS_RE = re.compile('\\b(?P<alias>local_\\w+|uVar\\d+|lVar\\d+|iVar\\d+|puVar\\d+)\\s*=\\s*(?:\\([^)]+\\)\\s*)?(?P<src>param_\\d+)\\b')
_LOCAL_ALIAS_RE = re.compile(r'\b(?P<dst>(?:local_[0-9A-Za-z_]+|[a-z]Var\d+))\s*=\s*(?:\([^)]+\)\s*)?(?P<src>(?:local_[0-9A-Za-z_]+|[a-z]Var\d+|param_\d+))\s*;')

@dataclass
class _JniCall:
    line: int
    jni_name: str
    category: str
    args: List[str]
    result_var: Optional[str]
    offset: Optional[str] = None
    resolved_strings: Dict[str, str] = field(default_factory=dict)
    resolved_ids: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    resolved_classes: Dict[str, str] = field(default_factory=dict)
    source_line: str = ''

@dataclass
class JnicRecoveryConfig:
    max_statements: int = 96
    decoded_strings: Dict[str, str] = field(default_factory=dict)
    class_internal: Optional[str] = None
    native_index: Optional[Dict[str, Any]] = None
    'Optional ``var_name → decoded literal`` map (e.g. from keystream).'

def _calls_for_function(jni_calls: Optional[Dict[str, Any]], fn_symbol: str) -> List[_JniCall]:
    if not isinstance(jni_calls, dict):
        return []
    raw = jni_calls.get('calls')
    if not isinstance(raw, list):
        return []
    out: List[_JniCall] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if entry.get('function') != fn_symbol:
            continue
        name = entry.get('jni_name')
        if not isinstance(name, str) or not name:
            continue
        args_raw = entry.get('args')
        if not isinstance(args_raw, list):
            args_raw = []
        out.append(_JniCall(line=int(entry.get('line') or 0), jni_name=name, category=str(entry.get('category') or 'other'), args=[str(a) for a in args_raw], result_var=str(entry.get('result_var')) if isinstance(entry.get('result_var'), str) else None, offset=str(entry.get('offset')) if isinstance(entry.get('offset'), str) else None, resolved_strings=dict(entry.get('resolved_strings') or {}), resolved_ids=dict(entry.get('resolved_ids') or {}), resolved_classes=dict(entry.get('resolved_classes') or {}), source_line=str(entry.get('source_line') or '')))
    out.sort(key=lambda c: c.line)
    return out

def _build_param_alias_map(block: str, param_names: Sequence[str], native_param_base: int, receiver_name: Optional[str]) -> Dict[str, str]:
    base: Dict[str, str] = {}
    if receiver_name:
        base['param_2'] = receiver_name
    for i, name in enumerate(param_names):
        base[f'param_{i + native_param_base}'] = name
    alias_map: Dict[str, str] = dict(base)
    for m in _PARAM_ALIAS_RE.finditer(block):
        src = m.group('src')
        alias = m.group('alias')
        if src in base and alias not in alias_map:
            alias_map[alias] = base[src]
    assignments: Dict[str, List[str]] = {}
    for match in _LOCAL_ALIAS_RE.finditer(block):
        assignments.setdefault(match.group('dst'), []).append(match.group('src'))
    for alias, sources in assignments.items():
        if len(sources) == 1 and alias not in alias_map and sources[0] != alias:
            alias_map[alias] = sources[0]
    return alias_map

def _build_arg_index_map(block: str, alias_map: Dict[str, str], args_param: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if args_param is None:
        return out
    for m in re.finditer('\\b(?P<dst>\\w+)\\s*=\\s*\\(\\*\\*\\(code\\s*\\*\\*\\)\\(\\*\\s*\\w+\\s*\\+\\s*0x568\\)\\)\\s*\\(\\s*\\w+\\s*,\\s*(?P<args>\\w+)\\s*,\\s*(?P<idx>\\d+)\\s*\\)', block):
        dst = m.group('dst')
        args_alias = m.group('args')
        idx = m.group('idx')
        if alias_map.get(args_alias) != args_param:
            continue
        out[dst] = f'{args_param}[{idx}]'
    return out
_INT_LITERAL_RE = re.compile('^[+-]?(?:0x[0-9A-Fa-f]+|\\d+)(?:[uUlL]+)?$')

def _is_int_literal(expr: str) -> bool:
    return bool(_INT_LITERAL_RE.match(expr.strip()))

def _detect_return_target(block: str, *, alias_map: Dict[str, str], arg_index_map: Dict[str, str], jni_result_locals: Dict[str, str]) -> Optional[str]:
    matches = list(_RETURN_RE.finditer(block))
    if not matches:
        return None
    last_expr = matches[-1].group('expr').strip()
    return _resolve_return_expr(last_expr, block=block, alias_map=alias_map, arg_index_map=arg_index_map, jni_result_locals=jni_result_locals)

def _resolve_return_expr(expr: str, *, block: str, alias_map: Dict[str, str], arg_index_map: Dict[str, str], jni_result_locals: Dict[str, str]) -> Optional[str]:
    expr = expr.strip()
    if expr in alias_map:
        return alias_map[expr]
    if expr in arg_index_map:
        return arg_index_map[expr]
    if expr in jni_result_locals:
        return '__jni_result__'
    last_assign = None
    for m in re.finditer(f'\\b{re.escape(expr)}\\s*=\\s*(?P<rhs>[^;]{{1,120}});', block):
        last_assign = m.group('rhs').strip()
    if isinstance(last_assign, str) and last_assign:
        if last_assign in alias_map:
            return alias_map[last_assign]
        if last_assign in arg_index_map:
            return arg_index_map[last_assign]
        if last_assign in jni_result_locals:
            return '__jni_result__'
    return None

def _has_helper_native_dispatch(block: str) -> bool:
    return bool(re.search('\\(\\*\\(code\\s*\\*\\)\\(\\s*&(?:DAT|LAB)_[0-9A-Fa-f]+\\s*\\+', block) or re.search('FUN_[0-9A-Fa-f]+\\s*\\(\\s*param_1\\s*\\)', block) or re.search('\\(\\*\\(code\\s*\\*\\)\\([^)]{0,200}\\bDAT_[0-9A-Fa-f]+\\b[^)]*\\)\\)', block))
_CFF_JUMPTABLE_RE = re.compile('\\(\\*\\(code\\s*\\*\\)\\(\\s*&(?:DAT|LAB)_[0-9A-Fa-f]+\\s*\\+[^;]*?\\^\\s*(?P<key>0x[0-9A-Fa-f]+)', re.DOTALL)
_CFF_WARNING_RE = re.compile('(Could not recover jumptable|Treating indirect jump as call)', re.IGNORECASE)

def _flattening_dispatch_keys(block: str) -> Optional[List[str]]:
    if not isinstance(block, str) or not block:
        return None
    keys = [m.group('key') for m in _CFF_JUMPTABLE_RE.finditer(block)]
    if keys:
        seen: List[str] = []
        for k in keys:
            if k not in seen:
                seen.append(k)
        return seen
    if _CFF_WARNING_RE.search(block) and _has_helper_native_dispatch(block):
        return []
    return None

def _pattern_identity(*, calls: Sequence[_JniCall], block: str, alias_map: Dict[str, str], arg_index_map: Dict[str, str], ret_java: str, args_param: Optional[str]) -> Optional[List[str]]:
    if ret_java == 'void':
        return None
    if not args_param:
        return None
    if len(calls) > 4:
        return None
    elem_calls = [c for c in calls if c.jni_name == 'GetObjectArrayElement']
    if len(elem_calls) != 1:
        return None
    other = [c for c in calls if c.jni_name not in {'GetObjectArrayElement', 'ExceptionCheck'}]
    if other:
        return None
    target = _detect_return_target(block, alias_map=alias_map, arg_index_map=arg_index_map, jni_result_locals={})
    if not isinstance(target, str):
        return None
    if not target.startswith(f'{args_param}['):
        return None
    return [f'return {target};']

def _pattern_void_dispatch(*, calls: Sequence[_JniCall], block: str, ret_java: str) -> Optional[List[str]]:
    if calls:
        return None
    keys = _flattening_dispatch_keys(block)
    if keys is None:
        return None
    body: List[str] = []
    if ret_java != 'void':
        body.append(f'return {_default_return_expr(ret_java)};')
    return body if body else None
_RAW_VAR_RE = re.compile('^(?:u?Var\\d+|[a-z]Var\\d+|p[a-z]?Var\\d+|[abciulp]?Stack_[0-9A-Fa-f]+|local_[0-9A-Fa-f]+|auStack_[0-9A-Fa-f]+|a[a-z]Stack_[0-9A-Fa-f]+|_?_?DAT_[0-9A-Fa-f]+|_?UNK_[0-9A-Fa-f]+|param_\\d+|in_[A-Za-z0-9_]+|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|register0x[0-9A-Fa-f]+)$')
_EXPR_TOKEN_RE = re.compile(r'[A-Za-z_]\w*(?:\[[A-Za-z0-9_]+])?')
_JNI_PRIM_RETURN = {'Boolean': 'boolean', 'Byte': 'byte', 'Char': 'char', 'Short': 'short', 'Int': 'int', 'Long': 'long', 'Float': 'float', 'Double': 'double', 'Void': 'void', 'Object': 'Object'}
_KNOWN_JAVA_METHODS = {
    ('java/lang/System', 'getenv', 1): '(Ljava/lang/String;)Ljava/lang/String;',
    ('java/nio/file/Paths', 'get', 2): '(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;',
}

def _descriptor_type(descriptor: Optional[str]) -> Optional[str]:
    if not isinstance(descriptor, str) or not descriptor:
        return None
    primitives = {'V': 'void', 'Z': 'boolean', 'B': 'byte', 'C': 'char', 'S': 'short', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double'}
    if descriptor in primitives:
        return primitives[descriptor]
    if descriptor.startswith('L') and descriptor.endswith(';'):
        return descriptor[1:-1].replace('/', '.')
    if descriptor.startswith('['):
        component = _descriptor_type(descriptor[1:])
        return component + '[]' if component else 'Object[]'
    return None


def _method_descriptor_parts(info: Optional[Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
    signature = info.get('signature') if isinstance(info, dict) else None
    parsed = _jni_method_sig_to_java(signature) if isinstance(signature, str) else None
    if not parsed:
        return None, []
    return parsed[0], list(parsed[1])


def _class_type(raw: Optional[str]) -> Optional[str]:
    if not isinstance(raw, str) or not raw:
        return None
    return raw.replace('/', '.').replace('$', '.')


def _java_class_literal(raw: str) -> str:
    if raw.startswith('['):
        java_type = _descriptor_type(raw) or 'Object[]'
        return f'{java_type}.class'
    return f'{_class_type(raw) or "Object"}.class'


def _jni_call_return_type(jni_name: str) -> str:
    for kind, java in _JNI_PRIM_RETURN.items():
        if jni_name.endswith(kind + 'Method') or jni_name.endswith(kind + 'Field'):
            return java
    return 'Object'

class _TraceContext:

    def __init__(self, *, alias_map: Dict[str, str], arg_index_map: Dict[str, str], decoded: Dict[str, str]) -> None:
        self.alias_map = alias_map
        self.arg_index_map = arg_index_map
        self.decoded = decoded
        self.values: Dict[str, str] = dict(alias_map)
        self.values.update(arg_index_map)
        self._temps: Dict[str, str] = {}
        self._temp_n = 0
        self._enc: Dict[str, int] = {}

    def fresh_temp(self) -> str:
        name = f'v{self._temp_n}'
        self._temp_n += 1
        return name

    def temp_for(self, token: str) -> str:
        existing = self._temps.get(token)
        if existing is not None:
            return existing
        name = self.fresh_temp()
        self._temps[token] = name
        return name

    def enc_label(self, kind: str) -> str:
        idx = self._enc.get(kind, 0)
        self._enc[kind] = idx + 1
        return {'class': 'cls', 'method': 'm', 'field': 'f', 'str': 's'}.get(kind, 'x') + str(idx)

    def resolve(self, raw: Optional[str]) -> str:
        expr = str(raw or '').strip()
        if not expr:
            return 'null'
        if _is_int_literal(expr):
            return _clean_literal(expr)
        if expr in self.values:
            value = self.values[expr]
            seen = {expr}
            while value in self.values and value not in seen:
                seen.add(value)
                value = self.values[value]
            return value
        if expr in self.decoded:
            return _java_string_literal(self.decoded[expr])
        if re.fullmatch('[A-Za-z_]\\w*', expr):
            if _RAW_VAR_RE.match(expr):
                return self.temp_for(expr)
            return expr
        return self._clean_expr(expr)

    def _clean_expr(self, expr: str) -> str:

        def repl(m: 're.Match[str]') -> str:
            tok = m.group(0)
            if tok in self.values:
                return self.values[tok]
            if tok in self.decoded:
                return _java_string_literal(self.decoded[tok])
            if _RAW_VAR_RE.match(tok):
                return self.temp_for(tok)
            return tok
        cleaned = _EXPR_TOKEN_RE.sub(repl, expr)
        cleaned = re.sub('\\(([A-Za-z_]\\w*\\s*\\*\\s*\\*?\\s*)\\)', '', cleaned)
        cleaned = re.sub('\\((?:un)?(?:signed\\s+)?(?:u?int\\d*|u?long(?:long)?|u?short|u?char|byte|undefined\\d*|code|void|float|double|size_t|wchar_t)\\)', '', cleaned)
        cleaned = re.sub('&(?=[A-Za-z_(])', '', cleaned)
        cleaned = re.sub(r'\b0x[0-9A-Fa-f]{9,}(?![0-9A-Fa-fuUlL])', lambda match: match.group(0) + 'L', cleaned)
        return cleaned.strip()

def _coerce_numeric_argument(expr: str, target_type: str) -> str:
    concat = re.fullmatch(r'CONCAT(?P<high>\d+)(?P<low>\d+)\([^,]+,\s*(?P<value>[^)]+)\)', expr.strip())
    widths = {'byte': 1, 'char': 2, 'short': 2, 'int': 4, 'long': 8}
    if concat is not None and widths.get(target_type, 0) <= int(concat.group('low')):
        expr = concat.group('value').strip()
    match = _INT_LITERAL_RE.fullmatch(expr.strip())
    if match is None:
        return f'({target_type}) ({expr})' if target_type in {'byte', 'char', 'short', 'int'} else expr
    literal = expr.strip().rstrip('uUlL')
    value = int(literal, 16 if literal.lower().startswith('0x') else 10)
    if target_type in {'int', 'short', 'byte', 'char'}:
        if 0x80000000 <= value <= 0xffffffff:
            value -= 0x100000000
        return str(value)
    if target_type == 'long':
        return f'{value}L'
    return expr


def _clean_literal(expr: str) -> str:
    s = str(expr).strip().rstrip('uUlL')
    val = None
    try:
        val = int(s, 16) if s.lower().startswith('0x') else int(s, 10)
    except Exception:
        return s
    if val > 2147483647 or val < -2147483648:
        return f'{val}L'
    return str(val)

def _call_resolved_id(call: _JniCall, index: int) -> Optional[Dict[str, Any]]:
    if index >= len(call.args):
        return None
    info = call.resolved_ids.get(call.args[index])
    return info if isinstance(info, dict) else None


def _complete_method_info(info: Optional[Dict[str, Any]], native_index: Optional[Dict[str, Any]], argument_count: int) -> Optional[Dict[str, Any]]:
    if not isinstance(info, dict) or info.get('signature'):
        return info
    owner, name = info.get('class'), info.get('name')
    known = _KNOWN_JAVA_METHODS.get((owner, name, argument_count))
    if known:
        return {**info, 'signature': known}
    if not isinstance(native_index, dict):
        return info
    matches: List[Dict[str, Any]] = []
    for item in native_index.get('methods', []):
        if not isinstance(item, dict) or item.get('class') != owner or item.get('method') != name:
            continue
        descriptor = item.get('descriptor')
        parsed = _jni_method_sig_to_java(descriptor) if isinstance(descriptor, str) else None
        if parsed is not None and len(parsed[1]) == argument_count:
            matches.append(item)
    if len(matches) != 1:
        return info
    return {**info, 'signature': matches[0]['descriptor']}


def _pattern_primitive_cache_decrypt(*, calls: Sequence[_JniCall], block: str, param_types: Sequence[str], param_names: Sequence[str], ret_java: str) -> Optional[List[str]]:
    if list(param_types) != ['int', 'long'] or len(param_names) != 2 or ret_java not in {'int', 'long'}:
        return None
    field_infos = [
        _call_resolved_id(call, 2)
        for call in calls
        if call.jni_name == 'GetStaticObjectField' and _call_resolved_id(call, 2)
    ]
    wrapper_suffix = 'Integer;' if ret_java == 'int' else 'Long;'
    cache = next((info for info in field_infos if str(info.get('signature') or '').startswith('[L') and str(info.get('signature')).endswith(wrapper_suffix)), None)
    source = next((info for info in field_infos if info.get('signature') == '[J'), None)
    value_of_call = next((call for call in calls if call.jni_name == 'CallStaticObjectMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'valueOf'), None)
    unbox_name = 'intValue' if ret_java == 'int' else 'longValue'
    unbox_call = next((call for call in calls if call.jni_name in {'CallIntMethod', 'CallLongMethod'} and (_call_resolved_id(call, 2) or {}).get('name') == unbox_name), None)
    if not all(isinstance(item, dict) for item in (cache, source)) or value_of_call is None or unbox_call is None:
        return None
    owner = _class_type(cache.get('class'))
    source_owner = _class_type(source.get('class'))
    cache_name = cache.get('name')
    source_name = source.get('name')
    if not owner or owner != source_owner or not all(isinstance(item, str) and item for item in (cache_name, source_name)):
        return None
    index_match = re.search(r'(?P<dst>\w+)\s*=\s*param_4\s*&\s*(?P<mask>0x[0-9A-Fa-f]+|\d+)\s*\^\s*param_3\s*\^\s*(?P<const>0x[0-9A-Fa-f]+|\d+)\s*;', block)
    index_variant = 'key_mask'
    if index_match is None:
        index_match = re.search(r'(?P<dst>\w+)\s*=\s*\(param_3\s*\^\s*\(uint\)param_4\)\s*&\s*(?P<mask>0x[0-9A-Fa-f]+|\d+)\s*\^\s*(?P<const>0x[0-9A-Fa-f]+|\d+)\s*;', block)
        index_variant = 'xor_mask'
    if index_match is None:
        return None
    mask = _clean_literal(index_match.group('mask'))
    constant = _clean_literal(index_match.group('const'))
    number, key = param_names
    index_expr = f'{number} ^ (int) ({key} & {mask}L) ^ {constant}' if index_variant == 'key_mask' else f'({number} ^ (int) {key}) & {mask} ^ {constant}'
    value_expr = f'{owner}.{source_name}[index] ^ {key}'
    if ret_java == 'int':
        value_expr = f'(int) ({value_expr})'
    wrapper = 'Integer' if ret_java == 'int' else 'Long'
    return [
        f'int index = {index_expr};',
        f'if ({owner}.{cache_name}[index] == null) {{',
        f'    {owner}.{cache_name}[index] = {wrapper}.valueOf({value_expr});',
        '}',
        f'return {owner}.{cache_name}[index].{unbox_name}();',
    ]

def _pattern_invokedynamic_dispatch(*, calls: Sequence[_JniCall], param_types: Sequence[str], param_names: Sequence[str], ret_java: str) -> Optional[List[str]]:
    simple_types = [item.replace('$', '.').rsplit('.', 1)[-1] for item in param_types]
    if simple_types != ['Lookup', 'MutableCallSite', 'String', 'MethodType', 'Object[]'] or len(param_names) != 5 or ret_java not in {'Object', 'java.lang.Object'}:
        return None
    long_calls = [call for call in calls if call.jni_name == 'CallLongMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'longValue']
    helper_call = next((call for call in calls if call.jni_name == 'CallStaticObjectMethod' and len(call.args) >= 9 and (_call_resolved_id(call, 2) or {}).get('name')), None)
    cast_call = next((call for call in calls if call.jni_name == 'CallStaticObjectMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'explicitCastArguments'), None)
    target_call = next((call for call in calls if call.jni_name == 'CallVoidMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'setTarget'), None)
    spread_call = next((call for call in calls if call.jni_name == 'CallObjectMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'asSpreader'), None)
    invoke_call = next((call for call in calls if call.jni_name == 'CallObjectMethod' and (_call_resolved_id(call, 2) or {}).get('name') == 'invokeWithArguments'), None)
    if len(long_calls) < 2 or any(call is None for call in (helper_call, cast_call, target_call, spread_call, invoke_call)):
        return None
    helper = _call_resolved_id(helper_call, 2)
    owner = _class_type((helper or {}).get('class'))
    method = (helper or {}).get('name')
    if not owner or not isinstance(method, str) or not method:
        return None
    lookup, call_site, name, method_type, args = param_names
    return [
        f'int index = {args}.length - 2;',
        f'long key1 = ((Long) {args}[index]).longValue();',
        f'long key2 = ((Long) {args}[++index]).longValue();',
        f'java.lang.invoke.MethodHandle target = {owner}.{method}({lookup}, {call_site}, {name}, {method_type}, key1, key2);',
        f'{call_site}.setTarget(java.lang.invoke.MethodHandles.explicitCastArguments(target, {method_type}));',
        f'return target.asSpreader(Object[].class, {args}.length).invoke({args});',
    ]


def _pattern_radioegor_invokedynamic_bootstrap(*, calls: Sequence[_JniCall], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    simple_types = [item.replace('$', '.').rsplit('.', 1)[-1] for item in param_types]
    if simple_types != ['Lookup', 'String', 'MethodType'] or len(param_names) != 3 or not ret_java.endswith('CallSite'):
        return None
    id_names = {
        str(info.get('name'))
        for call in calls for info in call.resolved_ids.values()
        if isinstance(info, dict) and info.get('name')
    }
    if not {'setTarget', 'explicitCastArguments'} <= id_names:
        return None
    if not any(call.jni_name == 'CallNonvirtualVoidMethod' for call in calls):
        return None
    if not any(call.jni_name == 'NewObjectArray' for call in calls):
        return None
    if sum(call.jni_name == 'SetObjectArrayElement' for call in calls) < 4:
        return None
    helper_descriptor = '(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/invoke/MutableCallSite;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/Object;'
    candidates = [
        item for item in (native_index or {}).get('methods', [])
        if isinstance(item, dict)
        and item.get('class') == class_internal
        and item.get('descriptor') == helper_descriptor
        and isinstance(item.get('method'), str)
    ]
    if len(candidates) != 1 or not class_internal:
        return None
    owner = class_internal.replace('/', '.').replace('$', '.')
    helper = candidates[0]['method']
    lookup, name, method_type = param_names
    return [
        f'java.lang.invoke.MutableCallSite callSite = new java.lang.invoke.MutableCallSite({method_type});',
        'try {',
        f'    java.lang.invoke.MethodHandle target = java.lang.invoke.MethodHandles.lookup().findStatic({owner}.class, "{helper}", java.lang.invoke.MethodType.methodType(Object.class, java.lang.invoke.MethodHandles.Lookup.class, java.lang.invoke.MutableCallSite.class, String.class, java.lang.invoke.MethodType.class, Object[].class));',
        f'    target = target.asCollector(Object[].class, {method_type}.parameterCount());',
        f'    target = java.lang.invoke.MethodHandles.insertArguments(target, 0, {lookup}, callSite, {name}, {method_type});',
        f'    callSite.setTarget(java.lang.invoke.MethodHandles.explicitCastArguments(target, {method_type}));',
        '} catch (Exception e) {',
        f'    throw new RuntimeException("{owner}" + " : " + e);',
        '}',
        'return callSite;',
    ]

def _pattern_radioegor_reflection_member_search(*, calls: Sequence[_JniCall], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    simple_types = [item.replace('$', '.').rsplit('.', 1)[-1] for item in param_types]
    descriptor = None
    if simple_types == ['Class', 'String', 'Class'] and ret_java.endswith('Field'):
        descriptor = '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/reflect/Field;'
    elif simple_types == ['Class', 'String', 'Class', 'int', 'Class[]'] and ret_java.endswith('Method'):
        descriptor = '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;I[Ljava/lang/Class;)Ljava/lang/reflect/Method;'
    if descriptor is None or not class_internal:
        return None
    companions = [
        item for item in (native_index or {}).get('methods', [])
        if isinstance(item, dict) and item.get('class') == class_internal and item.get('descriptor') == descriptor
    ]
    if len(companions) < 2:
        return None
    owner, name, member_type = param_names[:3]
    if ret_java.endswith('Field'):
        id_names = {
            str(info.get('name')) for call in calls for info in call.resolved_ids.values()
            if isinstance(info, dict) and info.get('name')
        }
        if 'getType' not in id_names or not any(call.jni_name == 'IsSameObject' for call in calls):
            return None
        return [
            f'for (java.lang.reflect.Field candidate : {owner}.getDeclaredFields()) {{',
            f'    if (candidate.getName().equals({name}) && candidate.getType() == {member_type}) {{',
            '        return candidate;',
            '    }',
            '}',
            'return null;',
        ]
    if not any(call.jni_name == 'GetArrayLength' for call in calls) or not any(call.jni_name == 'CallObjectMethod' for call in calls):
        return None
    count, expected = param_names[3:5]
    return [
        f'for (java.lang.reflect.Method candidate : {owner}.getDeclaredMethods()) {{',
        f'    if (candidate.getName().equals({name}) && candidate.getReturnType() == {member_type}) {{',
        '        Class<?>[] actual = candidate.getParameterTypes();',
        f'        if (actual.length == {count}) {{',
        '            int index = 0;',
        f'            while (index < {count} && actual[index] == {expected}[index]) {{',
        '                index++;',
        '            }',
        f'            if (index == {count}) {{',
        '                return candidate;',
        '            }',
        '        }',
        '    }',
        '}',
        'return null;',
    ]

def _pattern_radioegor_reflection_recursive_search(*, fn_symbol: str, jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    simple_types = [item.replace('$', '.').rsplit('.', 1)[-1] for item in param_types]
    if simple_types == ['Class', 'String', 'Class'] and ret_java.endswith('Field'):
        descriptor = '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/reflect/Field;'
        kind = 'Field'
    elif simple_types == ['Class', 'String', 'Class', 'int', 'Class[]'] and ret_java.endswith('Method'):
        descriptor = '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;I[Ljava/lang/Class;)Ljava/lang/reflect/Method;'
        kind = 'Method'
    else:
        return None
    companions = [item for item in (native_index or {}).get('methods', []) if isinstance(item, dict) and item.get('class') == class_internal and item.get('descriptor') == descriptor]
    current = [item for item in companions if item.get('fn_symbol') == fn_symbol]
    if len(companions) != 2 or len(current) != 1:
        return None
    raw_calls = [item for item in (jni_calls or {}).get('calls', []) if isinstance(item, dict)]
    direct = []
    for item in companions:
        candidate_calls = [call for call in raw_calls if call.get('function') == item.get('fn_symbol')]
        if kind == 'Field':
            names = {str(info.get('name')) for call in candidate_calls for info in (call.get('resolved_ids') or {}).values() if isinstance(info, dict) and info.get('name')}
            evidence = 'getType' in names and any(call.get('jni_name') == 'IsSameObject' for call in candidate_calls)
        else:
            evidence = any(call.get('jni_name') == 'GetArrayLength' for call in candidate_calls) and any(call.get('jni_name') == 'CallObjectMethod' for call in candidate_calls)
        if evidence:
            direct.append(item)
    if len(direct) != 1 or direct[0] is current[0]:
        return None
    direct_name = direct[0].get('method')
    recursive_name = current[0].get('method')
    if not all(isinstance(name, str) and name for name in (direct_name, recursive_name)):
        return None
    args = ', '.join(param_names)
    owner = param_names[0]
    recursive_args = ', '.join(param_names[1:])
    return [
        f'java.lang.reflect.{kind} candidate = {direct_name}({args});',
        'if (candidate != null) {',
        '    return candidate;',
        '}',
        f'Class<?>[] interfaces = {owner}.getInterfaces();',
        'if (interfaces != null) {',
        '    for (Class<?> parent : interfaces) {',
        f'        candidate = {recursive_name}(parent, {recursive_args});',
        '        if (candidate != null) {',
        '            return candidate;',
        '        }',
        '    }',
        '}',
        'return null;',
    ]

def _jnic_reflection_cache_fields(*, jni_calls: Optional[Dict[str, Any]], class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    if not class_internal:
        return None
    all_calls = [item for item in (jni_calls or {}).get('calls', []) if isinstance(item, dict)]
    initializers = [
        item for item in (native_index or {}).get('methods', [])
        if isinstance(item, dict) and item.get('class') == class_internal and item.get('descriptor') == '()V'
        and isinstance(item.get('fn_symbol'), str) and not str(item.get('method') or '').startswith('$')
    ]
    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for initializer in initializers:
        fields = [
            info for call in all_calls if call.get('function') == initializer['fn_symbol']
            for info in (call.get('resolved_ids') or {}).values()
            if isinstance(info, dict) and info.get('kind') == 'field' and info.get('class') == class_internal and info.get('static')
        ]
        caches = {str(info.get('name')): info for info in fields if info.get('signature') == '[Ljava/lang/Object;' and info.get('name')}
        names = {str(info.get('name')): info for info in fields if info.get('signature') == '[Ljava/lang/String;' and info.get('name')}
        if len(caches) == 1 and len(names) == 1:
            pairs.append((next(iter(caches.values())), next(iter(names.values()))))
    return pairs[0] if len(pairs) == 1 else None


def _pattern_radioegor_class_cache(*, fn_symbol: str, calls: Sequence[_JniCall], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    if list(param_types) != ['long', 'long'] or len(param_names) != 2 or not ret_java.endswith('Class') or not class_internal:
        return None
    methods = [item for item in (native_index or {}).get('methods', []) if isinstance(item, dict) and item.get('class') == class_internal]
    index_methods = [item for item in methods if item.get('descriptor') == '(JJ)I' and isinstance(item.get('method'), str)]
    if len(index_methods) != 1:
        return None
    pair = _jnic_reflection_cache_fields(jni_calls=jni_calls, class_internal=class_internal, native_index=native_index)
    cache, names = pair if pair is not None else (None, None)
    if not isinstance(cache, dict) or not isinstance(names, dict):
        return None
    if not any(call.jni_name == 'IsInstanceOf' for call in calls) or not any(call.jni_name == 'ExceptionOccurred' for call in calls):
        return None
    owner = class_internal.replace('/', '.').replace('$', '.')
    key1, key2 = param_names
    index_name = index_methods[0]['method']
    return [
        f'int index = {index_name}({key1}, {key2});',
        f'Object cached = {owner}.{cache["name"]}[index];',
        'try {',
        '    if (cached instanceof String) {',
        f'        Class<?> resolved = Class.forName({owner}.{names["name"]}[index]);',
        f'        {owner}.{cache["name"]}[index] = resolved;',
        '        return resolved;',
        '    }',
        '    return (Class) cached;',
        '} catch (Exception e) {',
        '    throw new RuntimeException(e.toString());',
        '}',
    ]

def _pattern_radioegor_member_cache(*, fn_symbol: str, calls: Sequence[_JniCall], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, class_internal: Optional[str], native_index: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    if list(param_types) != ['long', 'long'] or len(param_names) != 2 or not class_internal:
        return None
    kind = 'Field' if ret_java.endswith('Field') else 'Method' if ret_java.endswith('Method') else None
    if kind is None:
        return None
    methods = [item for item in (native_index or {}).get('methods', []) if isinstance(item, dict) and item.get('class') == class_internal]
    index = [item for item in methods if item.get('descriptor') == '(JJ)I']
    class_resolver = [item for item in methods if item.get('descriptor') == '(JJ)Ljava/lang/Class;']
    helper_desc = '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/reflect/Field;' if kind == 'Field' else '(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;I[Ljava/lang/Class;)Ljava/lang/reflect/Method;'
    helpers = [item for item in methods if item.get('descriptor') == helper_desc]
    if len(index) != 1 or len(class_resolver) != 1 or len(helpers) != 2:
        return None
    all_calls = [item for item in (jni_calls or {}).get('calls', []) if isinstance(item, dict)]
    direct = []
    for helper in helpers:
        helper_calls = [call for call in all_calls if call.get('function') == helper.get('fn_symbol')]
        if kind == 'Field':
            id_names = {str(info.get('name')) for call in helper_calls for info in (call.get('resolved_ids') or {}).values() if isinstance(info, dict) and info.get('name')}
            evidence = 'getType' in id_names and any(call.get('jni_name') == 'IsSameObject' for call in helper_calls)
        else:
            evidence = any(call.get('jni_name') == 'GetArrayLength' for call in helper_calls)
        if evidence:
            direct.append(helper)
    if len(direct) != 1:
        return None
    recursive = [item for item in helpers if item is not direct[0]]
    pair = _jnic_reflection_cache_fields(jni_calls=jni_calls, class_internal=class_internal, native_index=native_index)
    cache, names = pair if pair is not None else (None, None)
    if not isinstance(cache, dict) or not isinstance(names, dict) or len(recursive) != 1:
        return None
    if not any(call.jni_name == 'IsInstanceOf' for call in calls):
        return None
    owner = class_internal.replace('/', '.').replace('$', '.')
    index_name = index[0].get('method')
    class_name = class_resolver[0].get('method')
    recursive_name = recursive[0].get('method')
    if not all(isinstance(name, str) and name for name in (index_name, class_name, recursive_name)):
        return None
    key1, key2 = param_names
    prefix = [
        f'int index = {index_name}({key1}, {key2});',
        f'Object cached = {owner}.{cache["name"]}[index];',
        'if (!(cached instanceof String)) {',
        f'    return (java.lang.reflect.{kind}) cached;',
        '}',
        f'String specification = {owner}.{names["name"]}[index];',
        "String[] parts = specification.split(java.util.regex.Pattern.quote(String.valueOf('\\b')), -1);",
        f'Class<?> declaring = {class_name}(Long.parseLong(parts[0], 36), 0L);',
        'String memberName = parts[1];',
    ]
    if kind == 'Field':
        body = [
            f'Class<?> memberType = {class_name}(Long.parseLong(parts[2], 36), 0L);',
            'for (Class<?> current = declaring; current != null; current = current.getSuperclass()) {',
            f'    java.lang.reflect.Field resolved = {recursive_name}(current, memberName, memberType);',
            '    if (resolved != null) {',
            f'        {owner}.{cache["name"]}[index] = resolved;',
            '        return resolved;',
            '    }',
            '}',
            'throw new RuntimeException("NoSuchFieldException in " + declaring.getName() + " " + memberType.getName() + " " + memberName);',
        ]
    else:
        body = [
            'int parameterCount = parts.length - 3;',
            'Class<?>[] parameterTypes = new Class<?>[parameterCount];',
            'for (int i = 0; i < parameterCount; i++) {',
            f'    parameterTypes[i] = {class_name}(Long.parseLong(parts[i + 2], 36), 0L);',
            '}',
            f'Class<?> returnType = {class_name}(Long.parseLong(parts[parts.length - 1], 36), 0L);',
            'for (Class<?> current = declaring; current != null; current = current.getSuperclass()) {',
            f'    java.lang.reflect.Method resolved = {recursive_name}(current, memberName, returnType, parameterCount, parameterTypes);',
            '    if (resolved != null) {',
            f'        {owner}.{cache["name"]}[index] = resolved;',
            '        return resolved;',
            '    }',
            '}',
            'throw new RuntimeException("NoSuchMethodException in " + declaring.getName() + " " + returnType.getName() + " " + memberName);',
        ]
    return prefix + body

def _pattern_void_call_with_caught_exception(*, calls: Sequence[_JniCall], ret_java: str) -> Optional[List[str]]:
    if ret_java != 'void':
        return None
    field_call = next((call for call in calls if call.jni_name == 'GetLongField' and _call_resolved_id(call, 2)), None)
    static_call = next((call for call in calls if call.jni_name == 'CallStaticVoidMethod' and _call_resolved_id(call, 2)), None)
    exception_call = next((call for call in calls if call.jni_name == 'IsInstanceOf' and len(call.args) > 2), None)
    instance_calls = [
        call for call in calls
        if call.jni_name == 'CallVoidMethod' and _call_resolved_id(call, 2)
    ]
    if field_call is None or static_call is None or exception_call is None or len(instance_calls) != 1:
        return None
    field_info = _call_resolved_id(field_call, 2)
    static_info = _call_resolved_id(static_call, 2)
    handler_info = _call_resolved_id(instance_calls[0], 2)
    exception_class = exception_call.resolved_classes.get(exception_call.args[2])
    if not all(isinstance(item, dict) for item in (field_info, static_info, handler_info)):
        return None
    if field_info.get('signature') != 'J' or static_info.get('signature') != '(J)V' or handler_info.get('signature') != '()V':
        return None
    if not isinstance(exception_class, str):
        return None
    owner = _class_type(static_info.get('class'))
    field_name = field_info.get('name')
    static_name = static_info.get('name')
    handler_name = handler_info.get('name')
    if not all(isinstance(item, str) and item for item in (owner, field_name, static_name, handler_name)):
        return None
    exception_type = _class_type(exception_class)
    if not exception_type:
        return None
    return [
        'try {',
        f'    {owner}.{static_name}(this.{field_name});',
        f'}} catch ({exception_type} e) {{',
        f'    e.{handler_name}();',
        '}',
    ]


def _infinite_loop_key(block: str, source_line: str) -> Optional[Tuple[int, int]]:
    if not source_line:
        return None
    position = block.find(source_line.strip())
    if position < 0:
        return None
    starts = list(re.finditer(r'while\s*\(\s*true\s*\)\s*\{', block[:position], re.IGNORECASE))
    for match in reversed(starts):
        brace = block.find('{', match.start())
        depth = 0
        for index in range(brace, len(block)):
            if block[index] == '{':
                depth += 1
            elif block[index] == '}':
                depth -= 1
                if depth == 0:
                    if brace < position < index:
                        return brace, index
                    break
    return None


def _reconstruct_body(*, calls: Sequence[_JniCall], decoded: Dict[str, str], arg_index_map: Dict[str, str], alias_map: Dict[str, str], args_param: Optional[str], ret_java: str, block: str, native_index: Optional[Dict[str, Any]]=None) -> Optional[List[str]]:
    if not calls:
        return None
    ctx = _TraceContext(alias_map=alias_map, arg_index_map=arg_index_map, decoded=decoded)
    method_ids: Dict[str, Dict[str, Any]] = {}
    field_ids: Dict[str, str] = {}
    class_names: Dict[str, str] = {}
    allocations: Dict[str, Tuple[str, str]] = {}
    stmts: List[str] = []
    stmt_loops: List[Optional[Tuple[int, int]]] = []
    last_value: Optional[str] = None

    def emit(call: _JniCall, statement: str) -> None:
        stmts.append(statement)
        stmt_loops.append(_infinite_loop_key(block, call.source_line))
    writeback: Optional[str] = None
    max_stmts = 40
    concat_lowerings, skipped_calls = find_string_concat_lowerings(calls)

    def remember(result_var: Optional[str], expr: str) -> None:
        nonlocal last_value
        if isinstance(result_var, str) and result_var:
            ctx.values[result_var] = expr
        last_value = expr

    def call_args(call: _JniCall, skip: int, info: Optional[Dict[str, Any]]=None) -> str:
        parts = [_java_class_literal(call.resolved_classes[a]) if a in call.resolved_classes else ctx.resolve(a) for a in call.args[skip:]]
        _ret, expected = _method_descriptor_parts(info)
        for index, target_type in enumerate(expected):
            if index >= len(parts) or target_type in {'Object', 'java.lang.Object'}:
                continue
            if target_type == 'boolean' and parts[index] in {'0', '1'}:
                parts[index] = 'true' if parts[index] == '1' else 'false'
            elif target_type in {'byte', 'char', 'short', 'int', 'long'}:
                parts[index] = _coerce_numeric_argument(parts[index], target_type)
            elif target_type not in {'boolean', 'float', 'double'}:
                parts[index] = f'({target_type}) {parts[index]}'
        return ', '.join(parts)

    def resolved_string(call: _JniCall, index: int) -> Optional[str]:
        if index >= len(call.args):
            return None
        raw = call.args[index]
        value = call.resolved_strings.get(raw)
        if isinstance(value, str):
            return value
        value = ctx.decoded.get(raw)
        return value if isinstance(value, str) else None

    def resolved_id(call: _JniCall, index: int) -> Optional[Dict[str, Any]]:
        if index >= len(call.args):
            return None
        value = call.resolved_ids.get(call.args[index])
        return value if isinstance(value, dict) else None

    def resolved_class(call: _JniCall, index: int) -> Optional[str]:
        if index >= len(call.args):
            return None
        value = call.resolved_classes.get(call.args[index])
        return value if isinstance(value, str) else None
    for call_index, call in enumerate(calls):
        if len(stmts) >= max_stmts:
            break
        if call_index in concat_lowerings:
            raw = concat_lowerings[call_index]
            expression = render_string_concat(raw[-1], [ctx.resolve(argument) for argument in raw[:-1]])
            if expression is not None:
                remember(call.result_var, expression)
            continue
        if call_index in skipped_calls:
            continue
        name = call.jni_name
        if not isinstance(name, str) or not name:
            continue
        if name in {'ExceptionCheck', 'ExceptionOccurred', 'ExceptionClear', 'DeleteLocalRef', 'DeleteGlobalRef', 'PushLocalFrame', 'PopLocalFrame', 'EnsureLocalCapacity', 'MonitorEnter', 'MonitorExit'}:
            continue
        if name == 'GetObjectArrayElement':
            array = ctx.resolve(call.args[1]) if len(call.args) > 1 else (args_param or 'args')
            index = ctx.resolve(call.args[2]) if len(call.args) > 2 else '0'
            remember(call.result_var, f'{array}[{index}]')
            continue
        if name in {'NewGlobalRef', 'NewLocalRef', 'NewWeakGlobalRef'}:
            ref = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'null'
            remember(call.result_var, ref)
            continue
        if name == 'FindClass':
            label = resolved_string(call, 1)
            cls = label if isinstance(label, str) and label else ctx.enc_label('class')
            if call.result_var:
                class_names[call.result_var] = cls
            remember(call.result_var, _class_var(cls))
            continue
        if name in {'GetObjectClass'}:
            recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            var = ctx.fresh_temp()
            emit(call, f'Class<?> {var} = {recv}.getClass();')
            if call.result_var:
                class_names[call.result_var] = var
            remember(call.result_var, var)
            continue
        if name in {'GetMethodID', 'GetStaticMethodID'}:
            mlabel = resolved_string(call, 2)
            mname = mlabel if isinstance(mlabel, str) and mlabel else ctx.enc_label('method')
            if call.result_var:
                method_ids[call.result_var] = {'name': mname, 'class': class_names.get(call.args[1]) if len(call.args) > 1 else None, 'static': name == 'GetStaticMethodID'}
            continue
        if name in {'GetFieldID', 'GetStaticFieldID'}:
            flabel = resolved_string(call, 2)
            fname = flabel if isinstance(flabel, str) and flabel else ctx.enc_label('field')
            if call.result_var:
                field_ids[call.result_var] = fname
            continue
        if name.startswith('Call') and 'Method' in name:
            nonvirtual = name.startswith('CallNonvirtual')
            method_index = 3 if nonvirtual else 2
            argument_index = method_index + 1
            info = (method_ids.get(call.args[method_index]) or resolved_id(call, method_index)) if len(call.args) > method_index else None
            info = _complete_method_info(info, native_index, max(0, len(call.args) - argument_index))
            is_static = bool(info and info.get('static'))
            mname = (info or {}).get('name') or ctx.enc_label('method')
            recv_type = _class_type((info or {}).get('class'))
            if is_static:
                recv = recv_type or 'Cls'
            else:
                recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            if recv_type and not is_static and recv != 'this':
                recv = f'(({recv_type}) {recv})'
            args_str = call_args(call, argument_index, info)
            descriptor_ret, _descriptor_args = _method_descriptor_parts(info)
            if nonvirtual and mname == '<init>':
                allocation = allocations.get(call.args[1]) if len(call.args) > 1 else None
                if allocation is not None:
                    variable, allocated_type = allocation
                    emit(call, f'{_decl_type(allocated_type)} {variable} = new {allocated_type}({args_str});')
                continue
            ret = descriptor_ret or _jni_call_return_type(name)
            invoke = f'{recv}.{mname}({args_str})'
            if ret == 'void':
                emit(call, invoke + ';')
                last_value = None
            else:
                var = ctx.fresh_temp()
                emit(call, f'{_decl_type(ret)} {var} = {invoke};')
                remember(call.result_var, var)
            continue
        if name in {'NewObject', 'NewObjectA', 'NewObjectV', 'AllocObject'}:
            cls = class_names.get(call.args[1]) if len(call.args) > 1 else None
            cls = cls or resolved_class(call, 1) or 'Object'
            cls = _class_type(cls) or 'Object'
            args_str = call_args(call, 3) if name != 'AllocObject' else ''
            var = ctx.fresh_temp()
            if name == 'AllocObject' and call.result_var:
                allocations[call.result_var] = (var, cls)
            else:
                emit(call, f'{_decl_type(cls)} {var} = new {cls}({args_str});')
            remember(call.result_var, var)
            continue
        if name == 'NewObjectArray':
            length = ctx.resolve(call.args[1]) if len(call.args) > 1 else '0'
            element = _class_type(resolved_class(call, 2)) or 'Object'
            var = ctx.fresh_temp()
            emit(call, f'{element}[] {var} = new {element}[{length}];')
            remember(call.result_var, var)
            continue
        if name.startswith('Get') and name.endswith('Field'):
            field_info = resolved_id(call, 2)
            if isinstance(field_info, dict) and field_info.get('static'):
                recv = _class_type(field_info.get('class')) or 'Cls'
            else:
                recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            fname = field_ids.get(call.args[2]) if len(call.args) > 2 else None
            fname = fname or (field_info.get('name') if isinstance(field_info, dict) else None)
            fname = fname or ctx.enc_label('field')
            ret = _descriptor_type(field_info.get('signature')) if isinstance(field_info, dict) else None
            ret = ret or _jni_call_return_type(name)
            var = ctx.fresh_temp()
            emit(call, f'{_decl_type(ret)} {var} = {recv}.{fname};')
            remember(call.result_var, var)
            continue
        if name.startswith('Set') and name.endswith('Field'):
            field_info = resolved_id(call, 2)
            if isinstance(field_info, dict) and field_info.get('static'):
                recv = _class_type(field_info.get('class')) or 'Cls'
            else:
                recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            fname = field_ids.get(call.args[2]) if len(call.args) > 2 else None
            fname = fname or (field_info.get('name') if isinstance(field_info, dict) else None)
            fname = fname or ctx.enc_label('field')
            value = ctx.resolve(call.args[3]) if len(call.args) > 3 else 'null'
            field_type = _descriptor_type(field_info.get('signature')) if isinstance(field_info, dict) else None
            if field_type and field_type not in {'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double', 'Object', 'java.lang.Object'}:
                value = f'({field_type}) {value}'
            emit(call, f'{recv}.{fname} = {value};')
            continue
        if name == 'SetObjectArrayElement' and len(call.args) >= 4:
            arr = ctx.resolve(call.args[1])
            idx = ctx.resolve(call.args[2])
            value = ctx.resolve(call.args[3])
            emit(call, f'{arr}[{idx}] = {value};')
            if args_param and arr == args_param:
                writeback = f'{arr}[{idx}]'
            continue
        if name == 'GetArrayLength':
            arr = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'array'
            var = ctx.fresh_temp()
            emit(call, f'int {var} = {arr}.length;')
            remember(call.result_var, var)
            continue
        if name in {'NewStringUTF', 'NewString'}:
            label = resolved_string(call, 1)
            if isinstance(label, str):
                expr = _java_string_literal(label)
            else:
                expr = f'''"<enc:{ctx.enc_label('str')}>"'''
            var = ctx.fresh_temp()
            emit(call, f'String {var} = {expr};')
            remember(call.result_var, var)
            continue
        if name == 'ThrowNew':
            continue
        if name == 'Throw':
            continue
        if call.category in {'array', 'string'}:
            continue
    if not any(statement.strip() for statement in stmts):
        return None
    body: List[str] = []
    iterator_index = None
    iterator_condition = None
    for candidate_index, statement in enumerate(stmts):
        match = re.match(r'boolean\s+v\d+\s*=\s*(.+\.hasNext\(\));$', statement.strip())
        if match and any('.iterator()' in previous for previous in stmts[:candidate_index]):
            iterator_index = candidate_index
            iterator_condition = match.group(1)
            break
    if iterator_index is not None and iterator_condition is not None:
        body.extend(statement for statement in stmts[:iterator_index] if statement.strip())
        body.append(f'while ({iterator_condition}) {{')
        body.extend('    ' + statement for statement in stmts[iterator_index + 1:] if statement.strip())
        body.append('}')
        index = len(stmts)
    else:
        index = 0
    while index < len(stmts):
        loop_key = stmt_loops[index]
        if loop_key is None:
            if stmts[index].strip():
                body.append(stmts[index])
            index += 1
            continue
        body.append('while (true) {')
        while index < len(stmts) and stmt_loops[index] == loop_key:
            if stmts[index].strip():
                body.append('    ' + stmts[index])
            index += 1
        body.append('}')
    if ret_java != 'void':
        ret_expr = writeback or last_value
        if isinstance(ret_expr, str) and ret_expr:
            body.append(f'return {_cast_for_return(ret_java, ret_expr)};')
        else:
            body.append(f'return {_default_return_expr(ret_java)};')
    return body

def _decl_type(java_type: str) -> str:
    return java_type if java_type else 'Object'

def _class_var(cls: str) -> str:
    simple = re.split('[/.$]', cls)[-1] or 'cls'
    safe = re.sub('[^A-Za-z0-9_]', '', simple)
    if not safe or not safe[0].isalpha():
        return 'cls' + safe
    return safe[:1].lower() + safe[1:] + 'Class'

def _class_name_literal(cls: str) -> str:
    if re.fullmatch('(?:cls|m|f|s)\\d+', cls):
        return f'"<enc:{cls}>"'
    return _java_string_literal(cls.replace('/', '.'))

def _cast_for_return(ret_java: str, expr: str) -> str:
    if ret_java in {'Object', 'void'}:
        return expr
    if ret_java in {'int', 'long', 'short', 'byte', 'char', 'float', 'double', 'boolean'}:
        if _is_int_literal(expr) or re.fullmatch('v\\d+', expr):
            return expr
        return f'({ret_java}) {expr}'
    return f'({ret_java}) {expr}'

def _java_string_literal(value: str) -> str:
    replacements = {'\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f'}
    escaped = ''.join(replacements.get(char, f'\\u{ord(char):04x}' if ord(char) < 0x20 else char) for char in str(value))
    return f'"{escaped}"'

def _default_return_expr(ret_java: str) -> str:
    return {'boolean': 'false', 'int': '0', 'long': '0L', 'double': '0.0', 'float': '0.0f', 'char': '(char) 0', 'byte': '(byte) 0', 'short': '(short) 0'}.get(ret_java, 'null')

def recover_jnic_body(*, fn_symbol: str, block: Optional[str], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, native_param_base: int=3, receiver_name: Optional[str]=None, config: Optional[JnicRecoveryConfig]=None) -> Optional[List[str]]:
    if not isinstance(block, str) or not block.strip():
        return None
    cfg = config or JnicRecoveryConfig()
    calls = _calls_for_function(jni_calls, fn_symbol)
    alias_map = _build_param_alias_map(block, param_names, native_param_base, receiver_name)
    args_param: Optional[str] = None
    for i, t in enumerate(param_types):
        if t.endswith('[]'):
            if i < len(param_names):
                args_param = param_names[i]
                break
    if args_param is None and len(param_names) >= 2:
        args_param = param_names[-1]
    arg_index_map = _build_arg_index_map(block, alias_map, args_param)
    decoded = dict(cfg.decoded_strings or {})
    instruction_trace = any(getattr(call, 'source_line', '').upper().startswith('CALL ') for call in calls)
    producers = [
        lambda: _pattern_primitive_cache_decrypt(calls=calls, block=block, param_types=param_types, param_names=param_names, ret_java=ret_java),
        lambda: _pattern_invokedynamic_dispatch(calls=calls, param_types=param_types, param_names=param_names, ret_java=ret_java),
        lambda: recover_method_handle_resolver(fn_symbol=fn_symbol, calls=calls, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_radioegor_invokedynamic_bootstrap(calls=calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_radioegor_reflection_member_search(calls=calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_radioegor_reflection_recursive_search(fn_symbol=fn_symbol, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_radioegor_class_cache(fn_symbol=fn_symbol, calls=calls, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_radioegor_member_cache(fn_symbol=fn_symbol, calls=calls, jni_calls=jni_calls, param_types=param_types, param_names=param_names, ret_java=ret_java, class_internal=cfg.class_internal, native_index=cfg.native_index),
        lambda: _pattern_identity(calls=calls, block=block, alias_map=alias_map, arg_index_map=arg_index_map, ret_java=ret_java, args_param=args_param),
        lambda: _pattern_void_call_with_caught_exception(calls=calls, ret_java=ret_java),
    ]
    if not instruction_trace:
        producers.extend([
            lambda: _reconstruct_body(calls=calls, decoded=decoded, arg_index_map=arg_index_map, alias_map=alias_map, args_param=args_param, ret_java=ret_java, block=block, native_index=cfg.native_index),
            lambda: _pattern_void_dispatch(calls=calls, block=block, ret_java=ret_java),
        ])
    for producer in producers:
        body = producer()
        if isinstance(body, list) and body:
            return body
    return None
__all__ = ['JnicRecoveryConfig', 'recover_jnic_body']
