#!/usr/bin/env python3
"""Run pytest with a hard wall-clock timeout for the cutover gate."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


parser = argparse.ArgumentParser()
parser.add_argument("--timeout", type=float, default=90.0)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command and args.command[0] == "--" else args.command
if not command:
    parser.error("expected pytest command after --")

process = subprocess.Popen(command, start_new_session=True, text=True)
try:
    returncode = process.wait(timeout=args.timeout)
except subprocess.TimeoutExpired:
    print(f"TEST TIMEOUT after {args.timeout:.0f}s: {' '.join(command)}", file=sys.stderr)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
    raise SystemExit(124)
raise SystemExit(returncode)
