import re
from typing import Optional

def _ghidra_type_to_java(type_str: Optional[str], *, is_return: bool) -> str:
    if not type_str:
        return 'void' if is_return else 'long'
    t = str(type_str).strip().lower()
    if not t:
        return 'void' if is_return else 'long'
    if 'void' in t:
        return 'void' if is_return else 'long'
    jni_type_map = {'jboolean': 'boolean', 'jbyte': 'byte', 'jchar': 'char', 'jshort': 'short', 'jint': 'int', 'jsize': 'int', 'jlong': 'long', 'jfloat': 'float', 'jdouble': 'double', 'jstring': 'String', 'jclass': 'Class', 'jobject': 'Object', 'jthrowable': 'Throwable', 'jbooleanarray': 'boolean[]', 'jbytearray': 'byte[]', 'jchararray': 'char[]', 'jshortarray': 'short[]', 'jintarray': 'int[]', 'jlongarray': 'long[]', 'jfloatarray': 'float[]', 'jdoublearray': 'double[]', 'jobjectarray': 'Object[]'}
    compact_t = re.sub('\\s+', '', t).replace('*', '')
    if compact_t in jni_type_map:
        return jni_type_map[compact_t]
    if '*' in t:
        return 'long'
    if 'bool' in t:
        return 'boolean'
    if 'double' in t:
        return 'double'
    if 'float' in t:
        return 'float'
    if 'wchar' in t:
        return 'char'
    if 'int8' in t or 'uint8' in t:
        return 'byte'
    if 'int16' in t or 'uint16' in t:
        return 'short'
    if 'int64' in t or 'uint64' in t or 'undefined8' in t:
        return 'long'
    if 'int32' in t or 'uint32' in t or 'undefined4' in t:
        return 'int'
    if t in {'int', 'unsigned int'}:
        return 'int'
    if t in {'long', 'unsigned long', 'long long', 'unsigned long long'}:
        return 'long'
    if 'char' in t:
        return 'byte'
    if 'undefined' in t:
        return 'long'
    return 'long'

def _default_return_expr(java_type: str) -> Optional[str]:
    if java_type == 'void':
        return None
    if java_type == 'boolean':
        return 'false'
    if java_type == 'float':
        return '0.0f'
    if java_type == 'double':
        return '0.0d'
    if java_type == 'long':
        return '0L'
    if java_type == 'char':
        return "'\\0'"
    return '0'
