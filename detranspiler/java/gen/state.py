from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

@dataclass
class GenerationState:
    pseudo_c_text: Optional[str]
    by_name: Dict[str, str]
    ghidra_funcs: List[Dict[str, Any]]
    jar_meta: Any
    jni_hints: Dict[str, Any]
    flat_hints: Dict[str, Any]
    recovery_strategy: Any
    jar_index: Optional[Dict[str, Any]]
    helper_blocks: Dict[str, str]
    sig_by_raw: Dict[str, Tuple[str, List[Tuple[str, str]]]]
    sig_by_sanitized: Dict[str, Tuple[str, List[Tuple[str, str]]]]
    method_items: List[Tuple[str, str]]
    class_ident: str
    strings_by_addr: Dict[int, str]
    dat_ptr_values: Dict[str, int]
    jar_seed_strings: List[str]
    bin_seed_strings: List[str]
    read_string_at_va: Callable[[int], Optional[str]]
    read_u64_at_va: Callable[[int], Optional[int]]
    jni_calls: Optional[Dict[str, Any]] = None
    jni_register: Optional[Dict[str, Any]] = None
    flattening: Optional[Dict[str, Any]] = None
    anti_analysis: Optional[Dict[str, Any]] = None
    callgraph: Optional[Dict[str, Any]] = None
