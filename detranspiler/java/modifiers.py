from typing import List

def _access_flags_to_modifiers(flags: Optional[int], *, default_public: bool=True) -> Tuple[str, bool]:
    f = int(flags or 0)
    vis = ''
    if f & 1:
        vis = 'public'
    elif f & 2:
        vis = 'private'
    elif f & 4:
        vis = 'protected'
    elif default_public:
        vis = 'public'
    is_static = bool(f & 8)
    return vis, is_static
