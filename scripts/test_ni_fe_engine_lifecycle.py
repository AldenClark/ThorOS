#!/usr/bin/env python3
"""Compatibility entry point for the expanded production NI owner regression.

The former reset-on-every-open contract is deliberately gone. The executable
test now also covers retained EPP/BID/deepQ/TX state, partial initialization,
resource claims, physical reprobe, exported TX admission and actual removal.
"""
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).with_name('test_ni_owner_lifetime.py')), run_name='__main__')
