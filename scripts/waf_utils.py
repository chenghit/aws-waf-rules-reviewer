"""Shared utilities for WAF review scripts."""
import os
import sys


def fatal(msg: str):
    """Print FATAL result block and exit with code 2."""
    print(msg, file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: FATAL")
    print("ACTION: FIX")
    print(f"CONTEXT: {msg}")
    sys.exit(2)


def work_path(output_dir: str, name: str) -> str:
    """Path for an intermediate file. They live in {output_dir}/work so the
    report is the only thing at the top of output_dir."""
    d = os.path.join(output_dir, "work")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)
