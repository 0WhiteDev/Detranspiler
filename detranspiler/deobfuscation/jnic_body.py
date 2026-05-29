from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
_ARG_INDEX_RE = re.compile('\\(\\*\\*\\(code\\s*\\*\\*\\)\\(\\*\\s*\\w+\\s*\\+\\s*0x568\\)\\)\\s*\\(\\s*\\w+\\s*,\\s*(?P<args>\\w+)\\s*,\\s*(?P<idx>\\d+)\\s*\\)')
_RETURN_RE = re.compile('return\s+(?P<expr>[\w.\[\]+\-*/^&|<>!=, ]+);')
_PARAM_ALIAS_RE = re.compile('\\b(?P<alias>local_\\w+|uVar\\d+|lVar\\d+|iVar\\d+|puVar\\d+)\\s*=\\s*(?:\\([^)]+\\)\\s*)?(?P<src>param_\\d+)\\b')

@dataclass
class _JniCall:
    line: int
    jni_name: str
    category: str
    args: List[str]
    result_var: Optional[str]
    offset: Optional[str] = None

@dataclass
class JnicRecoveryConfig:
    max_statements: int = 96
    decoded_strings: Dict[str, str] = field(default_factory=dict)
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
        out.append(_JniCall(line=int(entry.get('line') or 0), jni_name=name, category=str(entry.get('category') or 'other'), args=[str(a) for a in args_raw], result_var=str(entry.get('result_var')) if isinstance(entry.get('result_var'), str) else None, offset=str(entry.get('offset')) if isinstance(entry.get('offset'), str) else None))
    out.sort(key=lambda c: c.line)
    return out

def _build_param_alias_map(block: str, param_names: Sequence[str], native_param_base: int) -> Dict[str, str]:
    base: Dict[str, str] = {}
    for i, name in enumerate(param_names):
        base[f'param_{i + native_param_base}'] = name
    alias_map: Dict[str, str] = dict(base)
    for m in _PARAM_ALIAS_RE.finditer(block):
        src = m.group('src')
        alias = m.group('alias')
        if src in base and alias not in alias_map:
            alias_map[alias] = base[src]
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
    for m in re.finditer(f'\\b{re.escape(expr)}\\s*=\\s*(?P<rhs>[^;]{ 1,120} );', block):
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
_EXPR_TOKEN_RE = re.compile('[A-Za-z_]\w*(?:\[[A-Za-z0-9_]+])?')
_JNI_PRIM_RETURN = {'Boolean': 'boolean', 'Byte': 'byte', 'Char': 'char', 'Short': 'short', 'Int': 'int', 'Long': 'long', 'Float': 'float', 'Double': 'double', 'Void': 'void', 'Object': 'Object'}

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
        self.values: Dict[str, str] = dict(arg_index_map)
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
            return self.values[expr]
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
        return cleaned.strip()

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

def _reconstruct_body(*, calls: Sequence[_JniCall], decoded: Dict[str, str], arg_index_map: Dict[str, str], alias_map: Dict[str, str], args_param: Optional[str], ret_java: str, block: str) -> Optional[List[str]]:
    if not calls:
        return None
    ctx = _TraceContext(alias_map=alias_map, arg_index_map=arg_index_map, decoded=decoded)
    method_ids: Dict[str, Dict[str, Any]] = {}
    field_ids: Dict[str, str] = {}
    class_names: Dict[str, str] = {}
    stmts: List[str] = []
    last_value: Optional[str] = None
    writeback: Optional[str] = None
    max_stmts = 40

    def remember(result_var: Optional[str], expr: str) -> None:
        nonlocal last_value
        if isinstance(result_var, str) and result_var:
            ctx.values[result_var] = expr
        last_value = expr

    def call_args(call: _JniCall, skip: int) -> str:
        parts = [ctx.resolve(a) for a in call.args[skip:]]
        return ', '.join(parts)
    for call in calls:
        if len(stmts) >= max_stmts:
            break
        name = call.jni_name
        if not isinstance(name, str) or not name:
            continue
        if name in {'ExceptionCheck', 'ExceptionOccurred', 'ExceptionClear', 'DeleteLocalRef', 'DeleteGlobalRef', 'PushLocalFrame', 'PopLocalFrame', 'EnsureLocalCapacity', 'MonitorEnter', 'MonitorExit', 'GetObjectArrayElement'}:
            continue
        if name in {'NewGlobalRef', 'NewLocalRef', 'NewWeakGlobalRef'}:
            ref = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'null'
            remember(call.result_var, ref)
            continue
        if name == 'FindClass':
            label = ctx.decoded.get(call.args[1]) if len(call.args) > 1 else None
            cls = label if isinstance(label, str) and label else ctx.enc_label('class')
            if call.result_var:
                class_names[call.result_var] = cls
            stmts.append(f'Class<?> {_class_var(cls)} = Class.forName({_class_name_literal(cls)});')
            remember(call.result_var, _class_var(cls))
            continue
        if name in {'GetObjectClass'}:
            recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            var = ctx.fresh_temp()
            stmts.append(f'Class<?> {var} = {recv}.getClass();')
            if call.result_var:
                class_names[call.result_var] = var
            remember(call.result_var, var)
            continue
        if name in {'GetMethodID', 'GetStaticMethodID'}:
            mlabel = ctx.decoded.get(call.args[2]) if len(call.args) > 2 else None
            mname = mlabel if isinstance(mlabel, str) and mlabel else ctx.enc_label('method')
            if call.result_var:
                method_ids[call.result_var] = {'name': mname, 'class': class_names.get(call.args[1]) if len(call.args) > 1 else None, 'static': name == 'GetStaticMethodID'}
            continue
        if name in {'GetFieldID', 'GetStaticFieldID'}:
            flabel = ctx.decoded.get(call.args[2]) if len(call.args) > 2 else None
            fname = flabel if isinstance(flabel, str) and flabel else ctx.enc_label('field')
            if call.result_var:
                field_ids[call.result_var] = fname
            continue
        if name.startswith('Call') and 'Method' in name:
            info = method_ids.get(call.args[2]) if len(call.args) > 2 else None
            is_static = bool(info and info.get('static'))
            mname = (info or {}).get('name') or ctx.enc_label('method')
            if is_static:
                recv = (info or {}).get('class') or 'Cls'
            else:
                recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            args_str = call_args(call, 3)
            ret = _jni_call_return_type(name)
            invoke = f'{recv}.{mname}({args_str})'
            if ret == 'void':
                stmts.append(invoke + ';')
                last_value = None
            else:
                var = ctx.fresh_temp()
                stmts.append(f'{_decl_type(ret)} {var} = {invoke};')
                remember(call.result_var, var)
            continue
        if name in {'NewObject', 'NewObjectA', 'NewObjectV', 'AllocObject'}:
            cls = class_names.get(call.args[1]) if len(call.args) > 1 else None
            cls = cls or 'Object'
            args_str = call_args(call, 3) if name != 'AllocObject' else ''
            var = ctx.fresh_temp()
            stmts.append(f'{_decl_type(cls)} {var} = new {cls}({args_str});')
            remember(call.result_var, var)
            continue
        if name == 'NewObjectArray':
            length = ctx.resolve(call.args[1]) if len(call.args) > 1 else '0'
            var = ctx.fresh_temp()
            stmts.append(f'Object[] {var} = new Object[{length}];')
            remember(call.result_var, var)
            continue
        if name.startswith('Get') and name.endswith('Field'):
            recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            fname = field_ids.get(call.args[2]) if len(call.args) > 2 else None
            fname = fname or ctx.enc_label('field')
            ret = _jni_call_return_type(name)
            var = ctx.fresh_temp()
            stmts.append(f'{_decl_type(ret)} {var} = {recv}.{fname};')
            remember(call.result_var, var)
            continue
        if name.startswith('Set') and name.endswith('Field'):
            recv = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'this'
            fname = field_ids.get(call.args[2]) if len(call.args) > 2 else None
            fname = fname or ctx.enc_label('field')
            value = ctx.resolve(call.args[3]) if len(call.args) > 3 else 'null'
            stmts.append(f'{recv}.{fname} = {value};')
            continue
        if name == 'SetObjectArrayElement' and len(call.args) >= 4:
            arr = ctx.resolve(call.args[1])
            idx = ctx.resolve(call.args[2])
            value = ctx.resolve(call.args[3])
            stmts.append(f'{arr}[{idx}] = {value};')
            if args_param and arr == args_param:
                writeback = f'{arr}[{idx}]'
            continue
        if name == 'GetArrayLength':
            arr = ctx.resolve(call.args[1]) if len(call.args) > 1 else 'array'
            var = ctx.fresh_temp()
            stmts.append(f'int {var} = {arr}.length;')
            remember(call.result_var, var)
            continue
        if name in {'NewStringUTF', 'NewString'}:
            label = ctx.decoded.get(call.args[1]) if len(call.args) > 1 else None
            if isinstance(label, str) and label:
                expr = _java_string_literal(label)
            else:
                expr = f'''"<enc:{ctx.enc_label('str')}>"'''
            var = ctx.fresh_temp()
            stmts.append(f'String {var} = {expr};')
            remember(call.result_var, var)
            continue
        if name == 'ThrowNew':
            continue
        if name == 'Throw':
            continue
        if call.category in {'array', 'string'}:
            continue
    real_stmts = [s for s in stmts if s.strip()]
    if not real_stmts:
        return None
    body: List[str] = list(real_stmts)
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
    escaped = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return f'"{escaped}"'

def _default_return_expr(ret_java: str) -> str:
    return {'boolean': 'false', 'int': '0', 'long': '0L', 'double': '0.0', 'float': '0.0f', 'char': '(char) 0', 'byte': '(byte) 0', 'short': '(short) 0'}.get(ret_java, 'null')

def recover_jnic_body(*, fn_symbol: str, block: Optional[str], jni_calls: Optional[Dict[str, Any]], param_types: Sequence[str], param_names: Sequence[str], ret_java: str, native_param_base: int=2, config: Optional[JnicRecoveryConfig]=None) -> Optional[List[str]]:
    if not isinstance(block, str) or not block.strip():
        return None
    cfg = config or JnicRecoveryConfig()
    calls = _calls_for_function(jni_calls, fn_symbol)
    alias_map = _build_param_alias_map(block, param_names, native_param_base)
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
    for producer in (lambda: _pattern_identity(calls=calls, block=block, alias_map=alias_map, arg_index_map=arg_index_map, ret_java=ret_java, args_param=args_param), lambda: _reconstruct_body(calls=calls, decoded=decoded, arg_index_map=arg_index_map, alias_map=alias_map, args_param=args_param, ret_java=ret_java, block=block), lambda: _pattern_void_dispatch(calls=calls, block=block, ret_java=ret_java)):
        body = producer()
        if isinstance(body, list) and body:
            return body
    return None
__all__ = ['JnicRecoveryConfig', 'recover_jnic_body']
