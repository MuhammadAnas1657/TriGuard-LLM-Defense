from .base import BaseDefense
from ..registry import DEFENSE_REGISTRY

# Import all defense modules to trigger @register_defense decorators
from . import defense_none  # noqa: F401
try: from .secalign import defense_secalign  # noqa: F401
except Exception: pass
try: from .pisanitizer import defense_pisanitizer  # noqa: F401
except Exception: pass
try: from .datasentinel import defense_datasentinel  # noqa: F401
except Exception: pass
try: from .attentiontracker import defense_attentiontracker  # noqa: F401
except Exception: pass
try: from .promptguard import defense_promptguard  # noqa: F401
except Exception: pass
try: from .promptlocate import defense_promptlocate  # noqa: F401
except Exception: pass
try: from .promptarmor import defense_promptarmor  # noqa: F401
except Exception: pass
try: from .datafilter import defense_datafilter  # noqa: F401
except Exception: pass
try: from .piguard import defense_piguard  # noqa: F401
except Exception: pass
try: from .triguard import defense_triguard  # noqa: F401
except Exception: pass

# Ensure src directory is in sys.path so triguard package is always resolvable
import sys
import os
_current_file = os.path.abspath(__file__)
_pkg_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_current_file))))
_src_dir = os.path.join(_pkg_root, "src")
for _p in [_src_dir, _pkg_root]:
    if _p not in sys.path and os.path.exists(_p):
        sys.path.insert(0, _p)

# Canonical TriGuard v2 Registration (maps both 'triguard' and 'triguard_v2' to TriGuardDefenseV2)
from triguard.defense_triguard_v2 import TriGuardDefenseV2
if "triguard" not in DEFENSE_REGISTRY._classes:
    DEFENSE_REGISTRY.register(TriGuardDefenseV2, name="triguard")
if "triguard_v2" not in DEFENSE_REGISTRY._classes:
    DEFENSE_REGISTRY.register(TriGuardDefenseV2, name="triguard_v2")

# Registry is auto-populated by @register_defense decorators
DEFENSE_CLASSES = DEFENSE_REGISTRY


def get_defense(name: str, config: dict = None) -> BaseDefense:
    """Factory: instantiate a defense by name."""
    cls = DEFENSE_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown defense: {name}. Available: {sorted(DEFENSE_REGISTRY.keys())}")
    return cls(config=config)
