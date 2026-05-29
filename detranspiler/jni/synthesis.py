import re
from typing import Any, Dict, List, Optional, Tuple

def _internal_to_java_class(internal: str) -> str:
    if not internal:
        return internal
    if internal.startswith('['):
        return internal
    if internal.startswith('L') and internal.endswith(';'):
        internal = internal[1:-1]
    return internal.replace('/', '.')

def _descriptor_arg_types(sig: str) -> List[str]:
    if not isinstance(sig, str) or not sig.startswith('('):
        return []
    i = 1
    out: List[str] = []
    while i < len(sig):
        ch = sig[i]
        if ch == ')':
            break
        if ch in 'BCDFIJSZ':
            mapping = {'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float', 'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean'}
            out.append(mapping[ch])
            i += 1
            continue
        if ch == 'L':
            j = sig.find(';', i)
            if j == -1:
                break
            out.append(_internal_to_java_class(sig[i:j + 1]))
            i = j + 1
            continue
        if ch == '[':
            j = i
            while j < len(sig) and sig[j] == '[':
                j += 1
            if j < len(sig) and sig[j] == 'L':
                k = sig.find(';', j)
                if k == -1:
                    break
                out.append(_internal_to_java_class(sig[i:k + 1]))
                i = k + 1
            else:
                out.append(_internal_to_java_class(sig[i:j + 1]))
                i = j + 1
            continue
        break
    return out

def _descriptor_return_type(sig: str) -> str:
    if not isinstance(sig, str) or ')' not in sig:
        return 'void'
    i = sig.index(')') + 1
    rest = sig[i:]
    if not rest or rest == 'V':
        return 'void'
    if rest == 'Z':
        return 'boolean'
    if rest == 'I':
        return 'int'
    if rest == 'J':
        return 'long'
    if rest == 'F':
        return 'float'
    if rest == 'D':
        return 'double'
    if rest == 'B':
        return 'byte'
    if rest == 'C':
        return 'char'
    if rest == 'S':
        return 'short'
    return _internal_to_java_class(rest)

def _java_escape(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\r', '\\r').replace('\n', '\\n')

def _unquote_c_string(expr: str) -> Optional[str]:
    s = str(expr or '').strip()
    for _ in range(4):
        m = re.match('^\(\s*[A-Za-z_][A-Za-z0-9_\s*]*\s*\)\s*(.+)$', s)
        if not m:
            break
        nxt = m.group(1).strip()
        if not nxt or nxt == s:
            break
        s = nxt
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return None
    return s[1:-1]

def _calls_for_function(jni_calls: Optional[Dict[str, Any]], fn_symbol: Optional[str]) -> List[Dict[str, Any]]:
    if not isinstance(jni_calls, dict) or not isinstance(fn_symbol, str) or (not fn_symbol):
        return []
    calls = jni_calls.get('calls')
    if not isinstance(calls, list):
        return []
    return [c for c in calls if isinstance(c, dict) and c.get('function') == fn_symbol]

def _resolve_call_arg(expr: str, *, string_vars: Dict[str, str], param_map: Dict[str, str]) -> Optional[str]:
    literal = _unquote_c_string(expr)
    if isinstance(literal, str):
        return f'"{_java_escape(literal)}"'
    var = str(expr or '').strip()
    if var in string_vars:
        return f'"{_java_escape(string_vars[var])}"'
    if var in param_map:
        return param_map[var]
    if re.fullmatch('param_\\d+', var) and var in param_map:
        return param_map[var]
    if re.fullmatch('[+-]?(?:0x[0-9A-Fa-f]+|\\d+)', var):
        return var
    return None

def _is_print_stream_method(cls: Optional[str], method: Optional[str], sig: Optional[str]) -> bool:
    if method != 'println':
        return False
    if isinstance(cls, str) and 'PrintStream' in cls:
        return True
    return sig == '(Ljava/lang/String;)V' or sig == '(I)V' or sig == '(J)V'

def _is_system_out_println(cls: Optional[str], method: Optional[str], sig: Optional[str]) -> bool:
    return _is_print_stream_method(cls, method, sig)

def _math_static_method(cls: Optional[str], method: Optional[str]) -> bool:
    return isinstance(cls, str) and cls.endswith('java/lang/Math') or cls == 'java/lang/Math'

def infer_java_body_from_jni_calls(*, fn_symbol: Optional[str], jni_calls: Optional[Dict[str, Any]], param_map: Optional[Dict[str, str]]=None, ret_java: str='void', java_param_names: Optional[List[str]]=None, max_statements: int=96) -> Optional[List[str]]:
    calls = _calls_for_function(jni_calls, fn_symbol)
    if not calls:
        return None
    param_map = dict(param_map or {})
    if java_param_names and (not any((k.startswith('param_') for k in param_map))):
        for idx, name in enumerate(java_param_names):
            param_map[f'param_{idx + 3}'] = name
    string_vars: Dict[str, str] = {}
    method_id_vars: Dict[str, Dict[str, Any]] = {}
    class_vars: Dict[str, str] = {}
    statements: List[str] = []
    pending_strings: List[str] = []
    return_expr: Optional[str] = None
    for call in calls:
        if len(statements) >= max_statements and return_expr is not None:
            break
        fn_name = call.get('jni_name')
        if not isinstance(fn_name, str) or not fn_name:
            continue
        args = call.get('args')
        if not isinstance(args, list):
            args = []
        result_var = call.get('result_var')
        resolved = call.get('resolved')
        if not isinstance(resolved, dict):
            resolved = {}
        if fn_name == 'NewStringUTF' and len(args) >= 2:
            lit = _unquote_c_string(args[1])
            if lit is None and isinstance(args[1], str):
                lit = string_vars.get(args[1].strip())
            if isinstance(lit, str):
                if isinstance(result_var, str) and result_var:
                    string_vars[result_var] = lit
                pending_strings.append(lit)
        if fn_name == 'FindClass' and len(args) >= 2:
            cls = resolved.get('class')
            if not isinstance(cls, str):
                lit = _unquote_c_string(args[1])
                cls = lit
            if isinstance(cls, str) and isinstance(result_var, str):
                class_vars[result_var] = cls
        if fn_name in {'GetMethodID', 'GetStaticMethodID'} and len(args) >= 4:
            info = {'class': resolved.get('class') or class_vars.get(str(args[1]).strip()), 'method': resolved.get('method'), 'signature': resolved.get('signature'), 'is_static': fn_name == 'GetStaticMethodID'}
            if not info['method']:
                lit = _unquote_c_string(args[2])
                if isinstance(lit, str):
                    info['method'] = lit
            if not info['signature']:
                lit = _unquote_c_string(args[3])
                if isinstance(lit, str):
                    info['signature'] = lit
            if isinstance(result_var, str) and info.get('method'):
                method_id_vars[result_var] = info
        if fn_name in {'GetObjectField', 'GetStaticObjectField'} and len(args) >= 3:
            field = resolved.get('field')
            if not isinstance(field, str):
                lit = _unquote_c_string(str(args[2]))
                field = lit
            recv = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            if isinstance(field, str) and recv and (ret_java != 'void'):
                return_expr = f'{recv}.{field}'
            continue
        _FIELD_GET = {'GetBooleanField': 'boolean', 'GetByteField': 'byte', 'GetCharField': 'char', 'GetShortField': 'short', 'GetIntField': 'int', 'GetLongField': 'long', 'GetFloatField': 'float', 'GetDoubleField': 'double', 'GetStaticBooleanField': 'boolean', 'GetStaticByteField': 'byte', 'GetStaticCharField': 'char', 'GetStaticShortField': 'short', 'GetStaticIntField': 'int', 'GetStaticLongField': 'long', 'GetStaticFloatField': 'float', 'GetStaticDoubleField': 'double'}
        if fn_name in _FIELD_GET and len(args) >= 3 and (ret_java == _FIELD_GET[fn_name]):
            field = resolved.get('field')
            if not isinstance(field, str):
                lit = _unquote_c_string(str(args[2]))
                field = lit
            recv = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            if fn_name.startswith('GetStatic') and isinstance(field, str):
                if ret_java != 'void':
                    return_expr = field
                continue
            if isinstance(field, str) and recv:
                return_expr = f'{recv}.{field}'
            continue
        _FIELD_SET = {'SetBooleanField': 'boolean', 'SetByteField': 'byte', 'SetCharField': 'char', 'SetShortField': 'short', 'SetIntField': 'int', 'SetLongField': 'long', 'SetFloatField': 'float', 'SetDoubleField': 'double', 'SetStaticBooleanField': 'boolean', 'SetStaticByteField': 'byte', 'SetStaticCharField': 'char', 'SetStaticShortField': 'short', 'SetStaticIntField': 'int', 'SetStaticLongField': 'long', 'SetStaticFloatField': 'float', 'SetStaticDoubleField': 'double'}
        if fn_name in _FIELD_SET and len(args) >= 4:
            field = resolved.get('field')
            if not isinstance(field, str):
                lit = _unquote_c_string(str(args[2]))
                field = lit
            recv = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            val = _resolve_call_arg(str(args[3]), string_vars=string_vars, param_map=param_map)
            if isinstance(field, str) and val:
                if fn_name.startswith('SetStatic'):
                    statements.append(f'{field} = {val};')
                elif recv:
                    statements.append(f'{recv}.{field} = {val};')
            continue
        if fn_name == 'GetObjectArrayElement' and len(args) >= 3 and (ret_java != 'void'):
            arr = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            idx = _resolve_call_arg(str(args[2]), string_vars=string_vars, param_map=param_map)
            if arr and idx:
                return_expr = f'{arr}[{idx}]'
            continue
        if fn_name == 'SetObjectArrayElement' and len(args) >= 4:
            arr = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            idx = _resolve_call_arg(str(args[2]), string_vars=string_vars, param_map=param_map)
            val = _resolve_call_arg(str(args[3]), string_vars=string_vars, param_map=param_map)
            if arr and idx and val:
                statements.append(f'{arr}[{idx}] = {val};')
            continue
        if fn_name in {'SetObjectField', 'SetStaticObjectField'} and len(args) >= 4:
            field = resolved.get('field')
            if not isinstance(field, str):
                lit = _unquote_c_string(str(args[2]))
                field = lit
            recv = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            val = _resolve_call_arg(str(args[3]), string_vars=string_vars, param_map=param_map)
            if isinstance(field, str) and recv and val:
                statements.append(f'{recv}.{field} = {val};')
            continue
        if fn_name == 'GetArrayLength' and len(args) >= 2:
            arr = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            if arr and ret_java == 'int':
                return_expr = f'{arr}.length'
            continue
        if fn_name == 'GetStringLength' and len(args) >= 2:
            s = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            if s and ret_java == 'int':
                return_expr = f'{s}.length()'
            continue
        if fn_name == 'IsInstanceOf' and len(args) >= 3 and (ret_java == 'boolean'):
            obj = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            cls = resolved.get('class')
            if not isinstance(cls, str):
                lit = _unquote_c_string(str(args[2]))
                cls = lit
            if obj and isinstance(cls, str):
                simple = _internal_to_java_class(cls).split('.')[-1]
                return_expr = f'{obj} instanceof {simple}'
            continue
        if fn_name == 'GetObjectClass' and len(args) >= 2 and (ret_java != 'void'):
            obj = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
            if obj:
                return_expr = f'{obj}.getClass()'
            continue
        if fn_name == 'ExceptionCheck' and ret_java == 'boolean':
            return_expr = 'false'
            continue
        if fn_name.startswith('Call') or fn_name.startswith('NewObject'):
            target = resolved.get('target_method')
            if not isinstance(target, dict) and len(args) > 2:
                mid_var = str(args[2]).strip()
                target = method_id_vars.get(mid_var)
            if not isinstance(target, dict) and isinstance(resolved.get('method'), str):
                target = {'class': resolved.get('class'), 'method': resolved.get('method'), 'signature': resolved.get('signature') or '()V', 'is_static': fn_name.startswith('CallStatic')}
            if isinstance(target, dict):
                cls = target.get('class')
                method = target.get('method')
                sig = target.get('signature')
                is_static = bool(target.get('is_static')) or fn_name.startswith('CallStatic')
                call_args: List[str] = []
                arg_types = _descriptor_arg_types(sig) if isinstance(sig, str) else []
                jni_arg_start = 3 if not fn_name.startswith('CallNonvirtual') else 4
                for ai, arg_expr in enumerate(args[jni_arg_start:]):
                    resolved_arg = _resolve_call_arg(str(arg_expr), string_vars=string_vars, param_map=param_map)
                    if resolved_arg is None and ai < len(java_param_names or []):
                        resolved_arg = (java_param_names or [])[ai]
                    if resolved_arg is not None:
                        call_args.append(resolved_arg)
                if pending_strings and (not call_args) and _is_system_out_println(cls, method, sig):
                    call_args = [f'"{_java_escape(pending_strings[-1])}"']
                    pending_strings.clear()
                if _is_system_out_println(cls, method, sig):
                    if call_args:
                        statements.append(f'System.out.println({call_args[0]});')
                    elif pending_strings:
                        statements.append(f'System.out.println("{_java_escape(pending_strings[-1])}");')
                        pending_strings.clear()
                    continue
                java_cls_name = _internal_to_java_class(cls) if isinstance(cls, str) else None
                if java_cls_name and java_cls_name.endswith('StringBuilder') and (method == 'append'):
                    if call_args:
                        if is_static and (not statements):
                            statements.append(f'StringBuilder sb = new StringBuilder({call_args[0]});')
                        else:
                            statements.append(f'sb.append({call_args[0]});')
                    continue
                if java_cls_name and java_cls_name.endswith('StringBuilder') and (method == 'toString'):
                    if ret_java == 'String':
                        return_expr = 'sb.toString()'
                    continue
                if java_cls_name == 'java.lang.String' and method == 'format' and call_args:
                    fmt = call_args[0]
                    rest = ', '.join(call_args[1:])
                    expr = f'String.format({fmt}, {rest})' if rest else f'String.format({fmt})'
                    if ret_java == 'String' and fn_name.startswith('Call'):
                        return_expr = expr
                    else:
                        statements.append(expr + ';')
                    continue
                if java_cls_name == 'java.lang.String' and method == 'equals' and call_args:
                    if ret_java == 'boolean' and len(call_args) >= 2:
                        return_expr = f'{call_args[0]}.equals({call_args[1]})'
                    elif ret_java == 'boolean':
                        return_expr = f'str.equals({call_args[0]})'
                    continue
                if java_cls_name == 'java.lang.String' and method == 'length':
                    if ret_java == 'int':
                        recv_arg = call_args[0] if call_args else 'str'
                        return_expr = f'{recv_arg}.length()'
                        continue
                if method == 'toString' and ret_java == 'String' and call_args:
                    recv_arg = call_args[0] if not is_static else call_args[0]
                    return_expr = f'{recv_arg}.toString()'
                    continue
                if fn_name == 'NewObject' and method == '<init>':
                    simple = _internal_to_java_class(cls).split('.')[-1] if isinstance(cls, str) else 'Object'
                    ctor_args = ', '.join(call_args) if call_args else ''
                    expr = f'new {simple}({ctor_args})'
                    if ret_java != 'void':
                        return_expr = expr
                    else:
                        statements.append(expr + ';')
                    continue
                if _math_static_method(cls if isinstance(cls, str) else None, method if isinstance(method, str) else None):
                    if isinstance(method, str) and method in {'abs', 'sqrt', 'round'} and call_args:
                        if ret_java != 'void' and fn_name.startswith('CallStatic'):
                            return_expr = f'Math.{method}({call_args[0]})'
                        else:
                            statements.append(f'Math.{method}({call_args[0]});')
                        continue
                    if isinstance(method, str) and method in {'max', 'min', 'pow'} and (len(call_args) >= 2):
                        expr = f'Math.{method}({call_args[0]}, {call_args[1]})'
                        if ret_java != 'void':
                            return_expr = expr
                        else:
                            statements.append(expr + ';')
                        continue
                if isinstance(method, str) and method in {'valueOf', 'parseInt', 'parseLong'}:
                    if call_args and ret_java in {'int', 'long', 'Integer', 'Long'}:
                        java_cls = _internal_to_java_class(cls) if isinstance(cls, str) else 'Integer'
                        expr = f'{java_cls}.{method}({call_args[0]})'
                        if ret_java != 'void':
                            return_expr = expr
                        else:
                            statements.append(expr + ';')
                        continue
                java_cls = _internal_to_java_class(cls) if isinstance(cls, str) else None
                java_method = method if isinstance(method, str) else None
                if java_method and (java_cls or not is_static):
                    if is_static and java_cls:
                        recv = java_cls.split('.')[-1]
                        stmt = f"{java_cls}.{java_method}({', '.join(call_args)})"
                    else:
                        recv = _resolve_call_arg(str(args[1]), string_vars=string_vars, param_map=param_map)
                        if not recv and call_args:
                            recv = call_args[0]
                        if not recv:
                            recv = 'obj'
                        stmt = f"{recv}.{java_method}({', '.join(call_args)})"
                    ret_type = _descriptor_return_type(sig) if isinstance(sig, str) else 'void'
                    if ret_type != 'void' and ret_java != 'void' and fn_name.startswith('Call'):
                        return_expr = stmt
                    else:
                        statements.append(stmt + ';')
        if fn_name == 'ThrowNew' and len(args) >= 3:
            cls = resolved.get('class') or class_vars.get(str(args[1]).strip())
            msg = _resolve_call_arg(str(args[2]), string_vars=string_vars, param_map=param_map)
            if isinstance(cls, str):
                simple = _internal_to_java_class(cls).split('.')[-1]
                if msg:
                    statements.append(f'throw new {simple}({msg});')
                else:
                    statements.append(f'throw new {simple}();')
        if fn_name == 'MonitorEnter':
            pass
        if fn_name == 'MonitorExit':
            pass
    if return_expr and ret_java != 'void':
        return statements + [f'return {return_expr};']
    if statements:
        return statements
    return None

def infer_java_return_from_jni_calls(*, fn_symbol: Optional[str], jni_calls: Optional[Dict[str, Any]], param_map: Optional[Dict[str, str]]=None, ret_java: str='void', java_param_names: Optional[List[str]]=None) -> Optional[str]:
    body = infer_java_body_from_jni_calls(fn_symbol=fn_symbol, jni_calls=jni_calls, param_map=param_map, ret_java=ret_java, java_param_names=java_param_names, max_statements=48)
    if not body or ret_java == 'void':
        return None
    for line in reversed(body):
        s = line.strip()
        if s.startswith('return '):
            return s[len('return '):].rstrip(';')
    return None
