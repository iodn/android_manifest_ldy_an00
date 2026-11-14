#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay a pinned patch series without mail-parser changes to commit metadata."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

source, series = Path(sys.argv[1]), Path(sys.argv[2])
data = json.loads(series.read_text())
def git(*args, **kwargs):
    return subprocess.check_output(["git", "-C", str(source), *args], **kwargs).strip()
if git("rev-parse", "HEAD", text=True) != data["base"]:
    raise SystemExit("Unexpected replay base")
if git("status", "--porcelain"):
    raise SystemExit("Replay requires a clean worktree")
for row in data["commits"]:
    patch = series.parent / row["patch"]
    if patch.parent != series.parent or hashlib.sha256(patch.read_bytes()).hexdigest() != row["patch_sha256"]:
        raise SystemExit("Patch identity mismatch")
    if git("rev-parse", "HEAD", text=True) != row["parent"]:
        raise SystemExit("Unexpected patch parent")
    subprocess.run(["git", "-C", str(source), "apply", "--index", str(patch)], check=True)
    if git("write-tree", text=True) != row["tree"]:
        raise SystemExit("Patch tree mismatch")
    env = os.environ.copy()
    for role in ("author", "committer"):
        for field in ("name", "email", "date"):
            env["GIT_" + role.upper() + "_" + field.upper()] = row[role][field]
    commit = git("commit-tree", row["tree"], "-p", row["parent"],
                 input=row["message"], text=True, env=env)
    if commit != row["commit"]:
        raise SystemExit("Replayed commit metadata mismatch")
    subprocess.run(["git", "-C", str(source), "update-ref", "HEAD", commit, row["parent"]], check=True)
if git("rev-parse", "HEAD", text=True) != data["head"] or git("status", "--porcelain"):
    raise SystemExit("Final replay identity mismatch")
print("KERNEL_PATCH_REPLAY_OK", data["head"])
