from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple


def _call_resolved_id(call: Any, index: int) -> Optional[Dict[str, Any]]:
    if index >= len(call.args):
        return None
    value = call.resolved_ids.get(call.args[index])
    return value if isinstance(value, dict) else None


def _java_string_literal(value: str) -> str:
    replacements = {
        "\\": "\\\\",
        '"': '\\"',
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\b": "\\b",
        "\f": "\\f",
    }
    escaped = "".join(
        replacements.get(char, f"\\u{ord(char):04x}" if ord(char) < 0x20 else char)
        for char in value
    )
    return f'"{escaped}"'


def find_string_concat_lowerings(calls: Sequence[Any]) -> Tuple[Dict[int, List[str]], set[int]]:
    lowerings: Dict[int, List[str]] = {}
    skipped: set[int] = set()
    for invoke_index, invoke in enumerate(calls):
        method = _call_resolved_id(invoke, 2)
        if invoke.jni_name != 'CallObjectMethod' or (method or {}).get('name') != 'invokeWithArguments' or len(invoke.args) < 4:
            continue
        array_symbol = invoke.args[3]
        array_index = next((
            index for index in range(invoke_index - 1, max(-1, invoke_index - 24), -1)
            if calls[index].jni_name == 'NewObjectArray' and calls[index].result_var == array_symbol
        ), None)
        if array_index is None:
            continue
        try:
            argument_count = int(calls[array_index].args[1], 0)
        except (IndexError, ValueError):
            continue
        elements: Dict[int, str] = {}
        for call in calls[array_index + 1:invoke_index]:
            if call.jni_name != 'SetObjectArrayElement' or len(call.args) < 4 or call.args[1] != array_symbol:
                continue
            try:
                elements[int(call.args[2], 0)] = call.args[3]
            except ValueError:
                continue
        if sorted(elements) != list(range(argument_count)):
            continue
        recipe_index = None
        recipe = None
        for index in range(array_index - 1, max(-1, array_index - 80), -1):
            call = calls[index]
            if call.jni_name != 'NewString' or len(call.args) < 2:
                continue
            candidate = call.resolved_strings.get(call.args[1])
            if isinstance(candidate, str) and '\x01' in candidate and '\x02' not in candidate and candidate.count('\x01') == argument_count:
                recipe_index, recipe = index, candidate
                break
        if recipe_index is None or recipe is None:
            continue
        window = calls[recipe_index:array_index]
        names = {(info or {}).get('name') for call in window for info in [_call_resolved_id(call, 2)]}
        if not {'findStatic', 'getTarget'} <= names:
            continue
        bootstrap_index = next((
            index for index in range(recipe_index - 1, max(-1, recipe_index - 32), -1)
            if calls[index].jni_name == 'NewObjectArray'
            and len(calls[index].args) > 1
            and calls[index].args[1] in {'4', '0x4'}
        ), None)
        if bootstrap_index is None:
            continue
        lowerings[invoke_index] = [elements[index] for index in range(argument_count)] + [recipe]
        skipped.update(range(bootstrap_index, invoke_index + 1))
    return lowerings, skipped


def render_string_concat(recipe: str, arguments: Sequence[str]) -> Optional[str]:
    if '\x02' in recipe or recipe.count('\x01') != len(arguments):
        return None
    parts: List[str] = []
    literals = recipe.split('\x01')
    for index, literal in enumerate(literals):
        if literal:
            parts.append(_java_string_literal(literal))
        if index < len(arguments):
            parts.append(f'String.valueOf({arguments[index]})')
    return ' + '.join(parts) if parts else '""'

