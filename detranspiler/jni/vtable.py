from typing import Any, Dict, List
JNI_INDEX_NAMES: Dict[int, str] = {4: 'GetVersion', 5: 'DefineClass', 6: 'FindClass', 7: 'FromReflectedMethod', 8: 'FromReflectedField', 9: 'ToReflectedMethod', 10: 'GetSuperclass', 11: 'IsAssignableFrom', 12: 'ToReflectedField', 13: 'Throw', 14: 'ThrowNew', 15: 'ExceptionOccurred', 16: 'ExceptionDescribe', 17: 'ExceptionClear', 18: 'FatalError', 19: 'PushLocalFrame', 20: 'PopLocalFrame', 21: 'NewGlobalRef', 22: 'DeleteGlobalRef', 23: 'DeleteLocalRef', 24: 'IsSameObject', 25: 'NewLocalRef', 26: 'EnsureLocalCapacity', 27: 'AllocObject', 28: 'NewObject', 29: 'NewObjectV', 30: 'NewObjectA', 31: 'GetObjectClass', 32: 'IsInstanceOf', 33: 'GetMethodID', 34: 'CallObjectMethod', 35: 'CallObjectMethodV', 36: 'CallObjectMethodA', 37: 'CallBooleanMethod', 38: 'CallBooleanMethodV', 39: 'CallBooleanMethodA', 40: 'CallByteMethod', 41: 'CallByteMethodV', 42: 'CallByteMethodA', 43: 'CallCharMethod', 44: 'CallCharMethodV', 45: 'CallCharMethodA', 46: 'CallShortMethod', 47: 'CallShortMethodV', 48: 'CallShortMethodA', 49: 'CallIntMethod', 50: 'CallIntMethodV', 51: 'CallIntMethodA', 52: 'CallLongMethod', 53: 'CallLongMethodV', 54: 'CallLongMethodA', 55: 'CallFloatMethod', 56: 'CallFloatMethodV', 57: 'CallFloatMethodA', 58: 'CallDoubleMethod', 59: 'CallDoubleMethodV', 60: 'CallDoubleMethodA', 61: 'CallVoidMethod', 62: 'CallVoidMethodV', 63: 'CallVoidMethodA', 64: 'CallNonvirtualObjectMethod', 65: 'CallNonvirtualObjectMethodV', 66: 'CallNonvirtualObjectMethodA', 67: 'CallNonvirtualBooleanMethod', 68: 'CallNonvirtualBooleanMethodV', 69: 'CallNonvirtualBooleanMethodA', 70: 'CallNonvirtualByteMethod', 71: 'CallNonvirtualByteMethodV', 72: 'CallNonvirtualByteMethodA', 73: 'CallNonvirtualCharMethod', 74: 'CallNonvirtualCharMethodV', 75: 'CallNonvirtualCharMethodA', 76: 'CallNonvirtualShortMethod', 77: 'CallNonvirtualShortMethodV', 78: 'CallNonvirtualShortMethodA', 79: 'CallNonvirtualIntMethod', 80: 'CallNonvirtualIntMethodV', 81: 'CallNonvirtualIntMethodA', 82: 'CallNonvirtualLongMethod', 83: 'CallNonvirtualLongMethodV', 84: 'CallNonvirtualLongMethodA', 85: 'CallNonvirtualFloatMethod', 86: 'CallNonvirtualFloatMethodV', 87: 'CallNonvirtualFloatMethodA', 88: 'CallNonvirtualDoubleMethod', 89: 'CallNonvirtualDoubleMethodV', 90: 'CallNonvirtualDoubleMethodA', 91: 'CallNonvirtualVoidMethod', 92: 'CallNonvirtualVoidMethodV', 93: 'CallNonvirtualVoidMethodA', 94: 'GetFieldID', 95: 'GetObjectField', 96: 'GetBooleanField', 97: 'GetByteField', 98: 'GetCharField', 99: 'GetShortField', 100: 'GetIntField', 101: 'GetLongField', 102: 'GetFloatField', 103: 'GetDoubleField', 104: 'SetObjectField', 105: 'SetBooleanField', 106: 'SetByteField', 107: 'SetCharField', 108: 'SetShortField', 109: 'SetIntField', 110: 'SetLongField', 111: 'SetFloatField', 112: 'SetDoubleField', 113: 'GetStaticMethodID', 114: 'CallStaticObjectMethod', 115: 'CallStaticObjectMethodV', 116: 'CallStaticObjectMethodA', 117: 'CallStaticBooleanMethod', 118: 'CallStaticBooleanMethodV', 119: 'CallStaticBooleanMethodA', 120: 'CallStaticByteMethod', 121: 'CallStaticByteMethodV', 122: 'CallStaticByteMethodA', 123: 'CallStaticCharMethod', 124: 'CallStaticCharMethodV', 125: 'CallStaticCharMethodA', 126: 'CallStaticShortMethod', 127: 'CallStaticShortMethodV', 128: 'CallStaticShortMethodA', 129: 'CallStaticIntMethod', 130: 'CallStaticIntMethodV', 131: 'CallStaticIntMethodA', 132: 'CallStaticLongMethod', 133: 'CallStaticLongMethodV', 134: 'CallStaticLongMethodA', 135: 'CallStaticFloatMethod', 136: 'CallStaticFloatMethodV', 137: 'CallStaticFloatMethodA', 138: 'CallStaticDoubleMethod', 139: 'CallStaticDoubleMethodV', 140: 'CallStaticDoubleMethodA', 141: 'CallStaticVoidMethod', 142: 'CallStaticVoidMethodV', 143: 'CallStaticVoidMethodA', 144: 'GetStaticFieldID', 145: 'GetStaticObjectField', 146: 'GetStaticBooleanField', 147: 'GetStaticByteField', 148: 'GetStaticCharField', 149: 'GetStaticShortField', 150: 'GetStaticIntField', 151: 'GetStaticLongField', 152: 'GetStaticFloatField', 153: 'GetStaticDoubleField', 154: 'SetStaticObjectField', 155: 'SetStaticBooleanField', 156: 'SetStaticByteField', 157: 'SetStaticCharField', 158: 'SetStaticShortField', 159: 'SetStaticIntField', 160: 'SetStaticLongField', 161: 'SetStaticFloatField', 162: 'SetStaticDoubleField', 163: 'NewString', 164: 'GetStringLength', 165: 'GetStringChars', 166: 'ReleaseStringChars', 167: 'NewStringUTF', 168: 'GetStringUTFLength', 169: 'GetStringUTFChars', 170: 'ReleaseStringUTFChars', 171: 'GetArrayLength', 172: 'NewObjectArray', 173: 'GetObjectArrayElement', 174: 'SetObjectArrayElement', 175: 'NewBooleanArray', 176: 'NewByteArray', 177: 'NewCharArray', 178: 'NewShortArray', 179: 'NewIntArray', 180: 'NewLongArray', 181: 'NewFloatArray', 182: 'NewDoubleArray', 183: 'GetBooleanArrayElements', 184: 'GetByteArrayElements', 185: 'GetCharArrayElements', 186: 'GetShortArrayElements', 187: 'GetIntArrayElements', 188: 'GetLongArrayElements', 189: 'GetFloatArrayElements', 190: 'GetDoubleArrayElements', 191: 'ReleaseBooleanArrayElements', 192: 'ReleaseByteArrayElements', 193: 'ReleaseCharArrayElements', 194: 'ReleaseShortArrayElements', 195: 'ReleaseIntArrayElements', 196: 'ReleaseLongArrayElements', 197: 'ReleaseFloatArrayElements', 198: 'ReleaseDoubleArrayElements', 199: 'GetBooleanArrayRegion', 200: 'GetByteArrayRegion', 201: 'GetCharArrayRegion', 202: 'GetShortArrayRegion', 203: 'GetIntArrayRegion', 204: 'GetLongArrayRegion', 205: 'GetFloatArrayRegion', 206: 'GetDoubleArrayRegion', 207: 'SetBooleanArrayRegion', 208: 'SetByteArrayRegion', 209: 'SetCharArrayRegion', 210: 'SetShortArrayRegion', 211: 'SetIntArrayRegion', 212: 'SetLongArrayRegion', 213: 'SetFloatArrayRegion', 214: 'SetDoubleArrayRegion', 215: 'RegisterNatives', 216: 'UnregisterNatives', 217: 'MonitorEnter', 218: 'MonitorExit', 219: 'GetJavaVM', 220: 'GetStringRegion', 221: 'GetStringUTFRegion', 222: 'GetPrimitiveArrayCritical', 223: 'ReleasePrimitiveArrayCritical', 224: 'GetStringCritical', 225: 'ReleaseStringCritical', 226: 'NewWeakGlobalRef', 227: 'DeleteWeakGlobalRef', 228: 'ExceptionCheck', 229: 'NewDirectByteBuffer', 230: 'GetDirectBufferAddress', 231: 'GetDirectBufferCapacity', 232: 'GetObjectRefType'}

def _function_category(name: str) -> str:
    if name in {'FindClass', 'GetObjectClass', 'GetSuperclass', 'IsAssignableFrom', 'IsInstanceOf'}:
        return 'class_lookup'
    if 'MethodID' in name:
        return 'method_lookup'
    if 'FieldID' in name:
        return 'field_lookup'
    if name.startswith('Call') or name.startswith('NewObject'):
        return 'java_call'
    if 'String' in name:
        return 'string'
    if 'Array' in name:
        return 'array'
    if name.startswith('Exception') or name in {'Throw', 'ThrowNew', 'FatalError'}:
        return 'exception'
    if name.endswith('Ref') or 'LocalFrame' in name:
        return 'reference'
    if name in {'RegisterNatives', 'UnregisterNatives'}:
        return 'native_registration'
    return 'other'

def jni_index_to_offset(index: int, *, pointer_size: int=8) -> int:
    return index * pointer_size

def offset_to_jni_candidates(offset: int) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for ptr_size in (8, 4):
        if offset % ptr_size != 0:
            continue
        index = offset // ptr_size
        name = JNI_INDEX_NAMES.get(index)
        if not name:
            continue
        candidates.append({'pointer_size': ptr_size, 'index': index, 'name': name, 'category': _function_category(name)})
    return candidates

def decode_jni_offset(offset: int) -> Dict[str, Any]:
    candidates = offset_to_jni_candidates(offset)
    if candidates:
        return {**candidates[0], 'alternates': candidates[1:]}
    return {'pointer_size': None, 'index': None, 'name': None, 'category': 'unknown', 'alternates': []}

def jni_name_to_offsets(name: str, *, pointer_sizes: tuple[int, ...]=(8, 4)) -> List[int]:
    index = None
    for idx, fn in JNI_INDEX_NAMES.items():
        if fn == name:
            index = idx
            break
    if index is None:
        return []
    return [jni_index_to_offset(index, pointer_size=ps) for ps in pointer_sizes]

def is_jni_offset(offset: int, name: str) -> bool:
    decoded = decode_jni_offset(offset)
    return decoded.get('name') == name
ENV_VTABLE_CALL = '\\(\\*\\*\\(code\\s+\\*\\*\\)\\(\\*\\s*(?P<env>\\w+)\\s*\\+\\s*(?P<offset>0x[0-9A-Fa-f]+|\\d+)\\)\\)'
