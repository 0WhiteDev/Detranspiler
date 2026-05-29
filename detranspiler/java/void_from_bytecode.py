import re
import struct
from typing import Any, Dict, List, Optional, Tuple
from detranspiler.java.identifiers import _sanitize_java_identifier

def _infer_java_void_body_from_bytecode(code: bytes, *, cp: Optional[List[Optional[Any]]], local_names: Optional[Dict[int, str]]=None, local_var_table: Optional[List[Dict[str, Any]]]=None, bootstrap_methods: Optional[List[Dict[str, Any]]]=None) -> Optional[List[str]]:
    if not isinstance(code, (bytes, bytearray)) or not code:
        return None
    if not isinstance(cp, list) or not cp:
        return None

    def java_escape_string_literal(s: str) -> str:
        out = s.replace('\\', '\\\\')
        out = out.replace('"', '\\"')
        out = out.replace('\r', '\\r')
        out = out.replace('\n', '\\n')
        return out

    def cp_utf8(idx: int) -> Optional[str]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        return v if isinstance(v, str) else None

    def cp_class_name(idx: int) -> Optional[str]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if not (isinstance(v, tuple) and len(v) == 2 and (v[0] == 'Class')):
            return None
        return cp_utf8(v[1])

    def cp_string_class_for_anewarray(idx: int) -> str:
        nm = cp_class_name(idx)
        if not isinstance(nm, str) or not nm:
            return 'Object'
        if nm == 'java/lang/Object':
            return 'Object'
        if nm == 'java/lang/String':
            return 'String'
        return 'Object'

    def cp_name_and_type(idx: int) -> Optional[Tuple[str, str]]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if not (isinstance(v, tuple) and len(v) == 3 and (v[0] == 'NameAndType')):
            return None
        n = cp_utf8(v[1])
        d = cp_utf8(v[2])
        if not isinstance(n, str) or not isinstance(d, str):
            return None
        return (n, d)

    def cp_methodref(idx: int) -> Optional[Tuple[str, str, str]]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if not (isinstance(v, tuple) and len(v) == 3 and (v[0] in {'Methodref', 'InterfaceMethodref'})):
            return None
        cls = cp_class_name(v[1])
        nt = cp_name_and_type(v[2])
        if not isinstance(cls, str) or nt is None:
            return None
        nm, ds = nt
        return (cls, nm, ds)

    def cp_methodhandle_methodref(idx: int) -> Optional[Tuple[str, str, str]]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if not (isinstance(v, tuple) and len(v) == 3 and (v[0] == 'MethodHandle')):
            return None
        _ref_kind, ref_index = (v[1], v[2])
        if not isinstance(ref_index, int):
            return None
        return cp_methodref(ref_index)

    def cp_fieldref(idx: int) -> Optional[Tuple[str, str, str]]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if not (isinstance(v, tuple) and len(v) == 3 and (v[0] == 'Fieldref')):
            return None
        cls = cp_class_name(v[1])
        nt = cp_name_and_type(v[2])
        if not isinstance(cls, str) or nt is None:
            return None
        nm, ds = nt
        return (cls, nm, ds)

    def cp_const(idx: int) -> Optional[Any]:
        if not isinstance(idx, int) or idx <= 0 or idx >= len(cp):
            return None
        v = cp[idx]
        if isinstance(v, tuple) and len(v) == 2 and (v[0] == 'String'):
            s = cp_utf8(v[1])
            return s
        if isinstance(v, tuple) and len(v) == 2 and (v[0] == 'Integer'):
            return int(v[1])
        return None

    def descriptor_arg_count(desc: str) -> int:
        if not isinstance(desc, str) or not desc.startswith('('):
            return 0
        i = 1
        c = 0
        while i < len(desc):
            ch = desc[i]
            if ch == ')':
                return c
            if ch in 'BCDFIJSZ':
                c += 1
                i += 1
                continue
            if ch == 'L':
                j = desc.find(';', i)
                if j == -1:
                    return c
                c += 1
                i = j + 1
                continue
            if ch == '[':
                i += 1
                while i < len(desc) and desc[i] == '[':
                    i += 1
                if i < len(desc) and desc[i] == 'L':
                    j = desc.find(';', i)
                    if j == -1:
                        return c
                    c += 1
                    i = j + 1
                else:
                    c += 1
                    i += 1
                continue
            return c
        return c

    def const_to_java_expr(v: Any) -> Optional[str]:
        if isinstance(v, str):
            return f'"{java_escape_string_literal(v)}"'
        if isinstance(v, int):
            return str(v)
        return None

    def build_concat_from_recipe(recipe: str, dyn_args: List[str], const_args: List[Any]) -> Optional[str]:
        if not isinstance(recipe, str):
            return None
        parts: List[Tuple[str, Any]] = []
        buf: List[str] = []
        arg_i = 0
        const_i = 0
        for ch in recipe:
            if ch == '\x01':
                if buf:
                    parts.append(('str', ''.join(buf)))
                    buf = []
                parts.append(('arg', arg_i))
                arg_i += 1
            elif ch == '\x02':
                if buf:
                    parts.append(('str', ''.join(buf)))
                    buf = []
                parts.append(('const', const_i))
                const_i += 1
            else:
                buf.append(ch)
        if buf:
            parts.append(('str', ''.join(buf)))
        out: List[str] = []
        for kind, val in parts:
            if kind == 'str':
                if isinstance(val, str) and val:
                    out.append(f'"{java_escape_string_literal(val)}"')
            elif kind == 'arg':
                if isinstance(val, int) and 0 <= val < len(dyn_args):
                    out.append(dyn_args[val])
            elif kind == 'const':
                if isinstance(val, int) and 0 <= val < len(const_args):
                    ce = const_to_java_expr(const_args[val])
                    if isinstance(ce, str):
                        out.append(ce)
        out = [x for x in out if isinstance(x, str) and x.strip()]
        if not out:
            return None
        return ' + '.join(out)

    def read_u1(b: bytes, o: int) -> Tuple[int, int]:
        return b[o], o + 1

    def read_u2(b: bytes, o: int) -> Tuple[int, int]:
        return struct.unpack_from('>H', b, o)[0], o + 2

    def read_s2(b: bytes, o: int) -> Tuple[int, int]:
        return struct.unpack_from('>h', b, o)[0], o + 2
    ins: List[Tuple[int, int, Tuple[Any, ...]]] = []
    o = 0
    while o < len(code):
        off = o
        op, o = read_u1(code, o)
        if op in {16}:
            v, o = read_u1(code, o)
            if v >= 128:
                v = v - 256
            ins.append((off, op, (v,)))
        elif op in {17}:
            v, o = read_s2(code, o)
            ins.append((off, op, (v,)))
        elif op in {18}:
            idx, o = read_u1(code, o)
            ins.append((off, op, (idx,)))
        elif op in {19, 20}:
            idx, o = read_u2(code, o)
            ins.append((off, op, (idx,)))
        elif op in {21, 54}:
            idx, o = read_u1(code, o)
            ins.append((off, op, (idx,)))
        elif op in {132}:
            idx, o = read_u1(code, o)
            inc, o = read_u1(code, o)
            if inc >= 128:
                inc = inc - 256
            ins.append((off, op, (idx, inc)))
        elif op in {153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 164, 165, 166, 168, 169, 170, 171}:
            rel, o = read_s2(code, o)
            ins.append((off, op, (rel,)))
        elif op in {163, 167}:
            rel, o = read_s2(code, o)
            ins.append((off, op, (rel,)))
        elif op in {178, 179, 182, 184}:
            idx, o = read_u2(code, o)
            ins.append((off, op, (idx,)))
        elif op in {180, 181}:
            idx, o = read_u2(code, o)
            ins.append((off, op, (idx,)))
        elif op == 186:
            idx, o = read_u2(code, o)
            z, o = read_u2(code, o)
            ins.append((off, op, (idx, z)))
        elif op == 189:
            idx, o = read_u2(code, o)
            ins.append((off, op, (idx,)))
        else:
            ins.append((off, op, ()))

    def const_int_from_op(op: int, args: Tuple[Any, ...]) -> Optional[int]:
        if op == 2:
            return -1
        if 3 <= op <= 8:
            return op - 3
        if op == 16 and args and isinstance(args[0], int):
            return int(args[0])
        if op == 17 and args and isinstance(args[0], int):
            return int(args[0])
        if op in {18, 19} and args and isinstance(args[0], int):
            c = cp_const(int(args[0]))
            return int(c) if isinstance(c, int) else None
        return None

    def const_str_from_op(op: int, args: Tuple[Any, ...]) -> Optional[str]:
        if op in {18, 19} and args and isinstance(args[0], int):
            c = cp_const(int(args[0]))
            return c if isinstance(c, str) else None
        return None
    loop_info: Optional[Tuple[int, int, int, int, int]] = None
    for i in range(0, max(0, len(ins) - 10)):
        o0, op0, a0 = ins[i]
        o1, op1, a1 = ins[i + 1]
        start = const_int_from_op(op0, a0)
        if start is None:
            continue
        var_idx: Optional[int] = None
        if op1 == 54 and a1 and isinstance(a1[0], int):
            var_idx = int(a1[0])
        elif 59 <= op1 <= 62:
            var_idx = op1 - 59
        if var_idx is None:
            continue
        o2, op2, a2 = ins[i + 2]
        if not (op2 == 21 and a2 and (int(a2[0]) == var_idx) or (26 <= op2 <= 29 and op2 - 26 == var_idx)):
            continue
        o3, op3, a3 = ins[i + 3]
        limit = const_int_from_op(op3, a3)
        if limit is None:
            continue
        o4, op4, a4 = ins[i + 4]
        if op4 != 163 or not a4:
            continue
        end_off = o4 + 3 + int(a4[0])
        found_iinc = False
        found_goto = False
        found_print = False
        goto_target = None
        for j in range(i + 5, min(len(ins), i + 80)):
            oj, opj, aj = ins[j]
            if oj >= end_off:
                break
            if opj == 132 and aj and (int(aj[0]) == var_idx) and (int(aj[1]) == 1):
                found_iinc = True
            if opj == 167 and aj:
                tgt = oj + 3 + int(aj[0])
                goto_target = tgt
                found_goto = True
            if opj == 182 and aj:
                mr = cp_methodref(int(aj[0]))
                if mr is not None and mr[1] == 'println':
                    found_print = True
        if found_iinc and found_goto and found_print and (goto_target == o2):
            loop_info = (o0, end_off, var_idx, start, limit)
            break

    def simulate(seg: List[Tuple[int, int, Tuple[Any, ...]]], *, reserved_names: Dict[int, str]) -> List[str]:
        out: List[str] = []
        stack: List[str] = []
        declared: set[str] = set()
        names: Dict[int, str] = dict(reserved_names)
        if isinstance(local_names, dict):
            for k, v in local_names.items():
                if isinstance(k, int) and isinstance(v, str) and v and (k not in names):
                    names[int(k)] = _sanitize_java_identifier(v)

        def lvt_name(idx: int, pc_off: int) -> Optional[str]:
            if not isinstance(local_var_table, list):
                return None
            best_nm = None
            best_start = None
            for e in local_var_table:
                if not isinstance(e, dict):
                    continue
                if int(e.get('index', -1)) != int(idx):
                    continue
                sp = e.get('start_pc')
                ln = e.get('length')
                nm = e.get('name')
                if not (isinstance(sp, int) and isinstance(ln, int) and isinstance(nm, str) and nm):
                    continue
                if sp <= pc_off < sp + ln:
                    if best_start is None or sp >= best_start:
                        best_start = sp
                        best_nm = nm
            return best_nm

        def lname(i: int, pc_off: int) -> str:
            n = lvt_name(i, pc_off)
            if isinstance(n, str) and n:
                names[i] = n
                return n
            n = names.get(i)
            if isinstance(n, str) and n:
                return n
            n = f'v{i}'
            names[i] = n
            return n
        for _off, op, a in seg:
            if op in {2, 3, 4, 5, 6, 7, 8, 16, 17, 18, 19}:
                s = const_str_from_op(op, a)
                if isinstance(s, str):
                    stack.append(f'"{java_escape_string_literal(s)}"')
                    continue
                iv = const_int_from_op(op, a)
                if isinstance(iv, int):
                    stack.append(str(iv))
                    continue
            if op == 178 and a:
                fr = cp_fieldref(int(a[0]))
                if fr is not None and fr[0] == 'java/lang/System' and (fr[1] == 'out'):
                    stack.append('System.out')
                else:
                    stack.append('<field>')
                continue
            if op == 189 and a:
                if not stack:
                    continue
                sz = stack.pop()
                cn = cp_string_class_for_anewarray(int(a[0]))
                stack.append(f'new {cn}[{sz}]')
                continue
            if op in {21} and a:
                stack.append(lname(int(a[0]), _off))
                continue
            if 26 <= op <= 29:
                stack.append(lname(op - 26, _off))
                continue
            if op == 54 and a:
                idx = int(a[0])
                if not stack:
                    continue
                expr = stack.pop()
                nm = lname(idx, _off)
                if nm not in declared:
                    out.append(f'int {nm} = {expr};')
                    declared.add(nm)
                else:
                    out.append(f'{nm} = {expr};')
                continue
            if 59 <= op <= 62:
                idx = op - 59
                if not stack:
                    continue
                expr = stack.pop()
                nm = lname(idx, _off)
                if nm not in declared:
                    out.append(f'int {nm} = {expr};')
                    declared.add(nm)
                else:
                    out.append(f'{nm} = {expr};')
                continue
            if op == 100:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    stack.append(f'{a0} - {b}')
                continue
            if op == 108:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    stack.append(f'{a0} / {b}')
                continue
            if op == 112:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    stack.append(f'{a0} % {b}')
                continue
            if op == 158:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    out.append(f'if ({a0} == {b}) {{}} ')
                continue
            if op == 160:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    out.append(f'if ({a0} == {b}) {{}} ')
                continue
            if op == 179 and a:
                fr = cp_fieldref(int(a[0]))
                if fr is not None:
                    cls = fr[0].replace('/', '.')
                    out.append(f"{cls}.{fr[1]} = {(stack.pop() if stack else 'null')};")
                continue
            if op == 180 and a:
                fr = cp_fieldref(int(a[0]))
                if fr is not None:
                    cls = fr[0].replace('/', '.')
                    stack.append(f'{cls}.{fr[1]}')
                continue
            if op in {172, 173, 174, 175, 176}:
                if stack:
                    out.append(f'return {stack.pop()};')
                continue
            if op == 104:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    stack.append(f'{a0} * {b}')
                continue
            if op == 96:
                if len(stack) >= 2:
                    b = stack.pop()
                    a0 = stack.pop()
                    stack.append(f'{a0} + {b}')
                continue
            if op == 184 and a:
                mr = cp_methodref(int(a[0]))
                if mr is not None and mr[0] == 'java/lang/String' and (mr[1] == 'format'):
                    if mr[2].startswith('(Ljava/lang/String;') and '[Ljava/lang/Object;' in mr[2]:
                        if len(stack) >= 2:
                            _arr = stack.pop()
                            fmt = stack.pop()
                            stack.append(f'String.format({fmt})')
                    elif stack:
                        arg = stack.pop()
                        stack.append(f'String.format({arg})')
                elif mr is not None and mr[0] == 'java/lang/Math' and (mr[1] in {'max', 'min', 'abs', 'sqrt', 'round'}):
                    argc = descriptor_arg_count(mr[2]) if isinstance(mr[2], str) else 0
                    if argc == 1 and stack:
                        stack.append(f'Math.{mr[1]}({stack.pop()})')
                    elif argc == 2 and len(stack) >= 2:
                        b = stack.pop()
                        a0 = stack.pop()
                        stack.append(f'Math.{mr[1]}({a0}, {b})')
                continue
            if op == 186:
                if not a:
                    continue
                indy_index = int(a[0])
                v = cp[indy_index] if 0 <= indy_index < len(cp) else None
                nt_desc = None
                bsm_index = None
                if isinstance(v, tuple) and len(v) == 3 and (v[0] == 'InvokeDynamic'):
                    bsm_index = int(v[1])
                    nt = cp_name_and_type(int(v[2]))
                    if nt is not None:
                        _nm, nt_desc = nt
                argc = descriptor_arg_count(nt_desc) if isinstance(nt_desc, str) else 0
                if argc <= 0 or len(stack) < argc:
                    continue
                dyn_args = [stack.pop() for _ in range(argc)][::-1]
                expr: Optional[str] = None
                if isinstance(bsm_index, int) and isinstance(bootstrap_methods, list) and (0 <= bsm_index < len(bootstrap_methods)):
                    bsm = bootstrap_methods[bsm_index]
                    if isinstance(bsm, dict):
                        mh = bsm.get('method_ref')
                        mref = cp_methodhandle_methodref(int(mh)) if isinstance(mh, int) else None
                        if mref is not None and mref[0] == 'java/lang/invoke/StringConcatFactory':
                            bargs = bsm.get('args')
                            if mref[1] == 'makeConcatWithConstants' and isinstance(bargs, list) and bargs:
                                recipe = cp_const(int(bargs[0]))
                                consts = [cp_const(int(x)) for x in bargs[1:]]
                                if isinstance(recipe, str):
                                    expr = build_concat_from_recipe(recipe, dyn_args, consts)
                            elif mref[1] == 'makeConcat':
                                expr = ' + '.join(dyn_args)
                if expr is None:
                    expr = ' + '.join(dyn_args)
                if expr:
                    stack.append(expr)
                continue
            if op == 182 and a:
                mr = cp_methodref(int(a[0]))
                if mr is not None and mr[1] == 'println':
                    if len(stack) >= 2:
                        arg = stack.pop()
                        recv = stack.pop()
                        if recv == 'System.out':
                            out.append(f'System.out.println({arg});')
                        else:
                            out.append(f'{recv}.println({arg});')
                elif mr is not None and mr[0] == 'java/lang/String' and (mr[1] == 'length'):
                    if stack:
                        recv = stack.pop()
                        stack.append(f'{recv}.length()')
                elif mr is not None and mr[0] == 'java/lang/String' and (mr[1] == 'equals'):
                    if len(stack) >= 2:
                        other = stack.pop()
                        recv = stack.pop()
                        stack.append(f'{recv}.equals({other})')
                elif mr is not None and mr[0] == 'java/lang/Math' and (mr[1] in {'max', 'min'}):
                    if len(stack) >= 2:
                        b = stack.pop()
                        a0 = stack.pop()
                        stack.append(f'Math.{mr[1]}({a0}, {b})')
                continue
        return out
    pre: List[Tuple[int, int, Tuple[Any, ...]]] = ins
    post: List[Tuple[int, int, Tuple[Any, ...]]] = []
    loop_stmt: Optional[List[str]] = None
    if loop_info is not None:
        start_off, end_off, var_idx, start, limit = loop_info
        pre = [t for t in ins if t[0] < start_off]
        post = [t for t in ins if t[0] >= end_off]
        loop_var_name = 'i'
        if isinstance(local_var_table, list):
            best_nm = None
            best_start = None
            for e in local_var_table:
                if not isinstance(e, dict):
                    continue
                if int(e.get('index', -1)) != int(var_idx):
                    continue
                sp = e.get('start_pc')
                ln = e.get('length')
                nm = e.get('name')
                if not (isinstance(sp, int) and isinstance(ln, int) and isinstance(nm, str) and nm):
                    continue
                if sp <= start_off < sp + ln:
                    if best_start is None or sp >= best_start:
                        best_start = sp
                        best_nm = nm
            if isinstance(best_nm, str) and best_nm:
                loop_var_name = best_nm
        elif isinstance(local_names, dict):
            nm = local_names.get(int(var_idx))
            if isinstance(nm, str) and nm:
                loop_var_name = _sanitize_java_identifier(nm)
        loop_stmt = [f'for (int {loop_var_name} = {start}; {loop_var_name} <= {limit}; {loop_var_name}++) {{', f'  System.out.println({loop_var_name});', '}']
    pre_lines = simulate(pre, reserved_names={})
    post_lines = simulate(post, reserved_names={})
    out: List[str] = []
    out.extend(pre_lines)
    if isinstance(loop_stmt, list):
        out.extend(loop_stmt)
    out.extend(post_lines)
    out = [ln for ln in out if isinstance(ln, str) and ln.strip()]
    if len(out) > 200:
        out = out[:200]
    return out if out else None
