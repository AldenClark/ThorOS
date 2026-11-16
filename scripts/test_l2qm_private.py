#!/usr/bin/env python3
"""Compatibility entry point for the public-source L2QM baseline regression.

The maintained test covers the real native initializer and inherited selectors;
its optional pinned SDK oracle does not require a private stock module or Git
history. All command-line arguments are forwarded unchanged.
"""
from pathlib import Path
import runpy

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).with_name('test_l2qm_baseline.py')),
                  run_name='__main__')
