#!/usr/bin/env python3
"""Train all required neural models."""

from __future__ import annotations

import argparse
import subprocess
import sys

import _bootstrap  # noqa: F401


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--sample-limit", type=int)
    parser.add_argument("--models", nargs="+", default=["original", "normalized", "attention", "signal"])
    args = parser.parse_args()
    for model_name in args.models:
        cmd = [sys.executable, "scripts/train_bilstm.py", "--model", model_name, "--epochs", str(args.epochs), "--batch", str(args.batch)]
        if args.sample_limit:
            cmd.extend(["--sample-limit", str(args.sample_limit)])
        print(f"[*] Running {' '.join(cmd)}")
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
