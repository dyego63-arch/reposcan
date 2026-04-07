"""
Git hook installation for RepoScan.

Writes a shell script into .git/hooks/ that invokes ``reposcan scan``
before a commit or push.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from reposcan import __version__


# ---------------------------------------------------------------------------
# Hook template
# ---------------------------------------------------------------------------

_HOOK_TEMPLATE = r"""#!/usr/bin/env bash
# ── reposcan {hook_type} hook ──────────────────────────────────────────────
# Installed by reposcan v{version}
# https://github.com/KanavvGupta/reposcan
#
# Runs reposcan on your repo before each {action}.
# To bypass:  git {action} --no-verify
# ───────────────────────────────────────────────────────────────────────────

echo "🔍 reposcan: scanning repository..."

reposcan scan . --fail-on-ip-risk 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    echo ""
    echo "❌ reposcan: {action_cap} blocked — threats or IP-risk indicators detected."
    echo "   Review the findings above before proceeding."
    echo "   To bypass (NOT recommended): git {action} --no-verify"
    exit 1
elif [ $EXIT_CODE -eq 2 ]; then
    echo ""
    echo "⚠️  reposcan: Scanner error. {action_cap} allowed, but review manually."
    exit 0
fi

echo "✅ reposcan: No threats detected. Proceeding with {action}."
exit 0
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class HookError(Exception):
    """Raised when hook installation fails."""


def install_hook(
    repo_path: str = ".",
    hook_type: str = "pre-commit",
    force: bool = False,
) -> str:
    """
    Install a git hook in the repository at *repo_path*.

    Returns the absolute path of the created hook script.
    """
    repo = Path(repo_path).resolve()
    git_dir = repo / ".git"

    if not git_dir.is_dir():
        raise HookError(
            f"Not a git repository: {repo}\n"
            "Run 'git init' first, or specify the correct repo path."
        )

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / hook_type

    if hook_path.exists() and not force:
        raise HookError(
            f"Hook already exists: {hook_path}\n"
            "Use --force to overwrite."
        )

    action = hook_type.replace("pre-", "")

    script = _HOOK_TEMPLATE.format(
        hook_type=hook_type,
        version=__version__,
        action=action,
        action_cap=action.capitalize(),
    )

    hook_path.write_text(script, encoding="utf-8")

    # Make executable (Unix / macOS — harmless no-op on Windows)
    try:
        mode = hook_path.stat().st_mode
        hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    return str(hook_path)
