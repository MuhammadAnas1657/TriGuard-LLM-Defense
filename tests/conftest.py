# -*- coding: utf-8 -*-
"""
Pytest root configuration for TriGuard v2.
Ensures src and repo root are always present in sys.path in any external environment.
"""

import sys
import os

test_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(test_dir)
src_dir = os.path.join(repo_root, "src")

for path in [src_dir, repo_root]:
    if path not in sys.path and os.path.exists(path):
        sys.path.insert(0, path)

