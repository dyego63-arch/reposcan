"""
CLI argument parsing and command dispatch for RepoScan.

Subcommands:
    start      – One-command quickstart: scans CWD with full interactive TUI.
    scan       – Scan a directory for threats (flags: --json, --auto, etc.).
    version    – Print version and branding info.
    signatures – Show loaded signature database details.
    init-hook  – Install a git pre-commit / pre-push hook.

RepoScan finds suspicious artifacts in cloned repositories
before you trust them.
"""

from __future__ import annotations

import sys
import argparse

from reposcan import __version__
from reposcan import theme
from reposcan.scanner import (
    scan, scan_with_progress, ScanOptions, ScanError, ScanProgress,
)
from reposcan.reporter import (
    format_text, format_json, format_findings, format_summary,
    compute_exit_code,
)
from reposcan.signatures import load_signatures, SignatureLoadError
from reposcan.actions import run_action_menu, has_actionable_findings
from reposcan.theme import LoadingView


def main(argv: list[str] | None = None) -> None:
    """Main CLI entry point."""
    # Ensure UTF-8 output on Windows even when stdout is piped or
    # redirected (default cp1252 cannot encode the banner's block chars).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    parser = argparse.ArgumentParser(
        prog="reposcan",
        description=(
            "RepoScan finds suspicious artifacts in cloned "
            "repositories before you trust them."
        ),
        epilog=(
            theme.quick_guide_plain()
            + "\nCreated by THE ABOVE MINDSET  ·  https://github.com/KanavvGupta/reposcan\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global flags
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── start ─────────────────────────────────────────────────────────────
    sub.add_parser(
        "start",
        help="One-command quickstart: scan this folder interactively",
    )

    # ── scan ──────────────────────────────────────────────────────────────
    sp_scan = sub.add_parser(
        "scan",
        help="Scan a local directory or repository",
    )
    sp_scan.add_argument("path", help="Directory to scan")
    sp_scan.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output results as JSON (no colors/art)",
    )
    sp_scan.add_argument(
        "--no-color", action="store_true", dest="scan_no_color",
        help="Disable colored output",
    )
    sp_scan.add_argument(
        "--no-ip-checks", action="store_true",
        help="Skip IP/leak-risk indicator checks",
    )
    sp_scan.add_argument(
        "--fail-on-ip-risk", action="store_true",
        help="Exit 1 on IP/leak-risk findings (default: advisory only)",
    )
    sp_scan.add_argument(
        "--signatures-dir",
        help="Path to custom signatures directory",
    )
    sp_scan.add_argument(
        "--exclude", action="append", default=[],
        help="Glob pattern to exclude (repeatable)",
    )
    sp_scan.add_argument(
        "--follow-symlinks", action="store_true",
        help="Follow symbolic links during scan",
    )
    sp_scan.add_argument(
        "--auto", "--interactive", action="store_true",
        dest="interactive",
        help="Show interactive action menu after scan (like 'start')",
    )
    sp_scan.add_argument(
        "--no-heuristics", action="store_true",
        help="Disable built-in heuristic detection",
    )

    # ── version ───────────────────────────────────────────────────────────
    sub.add_parser("version", help="Show version information")

    # ── signatures ────────────────────────────────────────────────────────
    sp_sigs = sub.add_parser(
        "signatures",
        help="Show loaded signature database details",
    )
    sp_sigs.add_argument(
        "--signatures-dir",
        help="Path to custom signatures directory",
    )

    # ── init-hook ─────────────────────────────────────────────────────────
    sp_hook = sub.add_parser(
        "init-hook",
        help="Install a git hook for automatic scanning",
    )
    sp_hook.add_argument(
        "--pre-commit", action="store_const", const="pre-commit",
        dest="hook_type", help="Install as pre-commit hook (default)",
    )
    sp_hook.add_argument(
        "--pre-push", action="store_const", const="pre-push",
        dest="hook_type", help="Install as pre-push hook",
    )
    sp_hook.add_argument(
        "--force", action="store_true",
        help="Overwrite existing hook",
    )
    sp_hook.set_defaults(hook_type="pre-commit")

    # ── dispatch ──────────────────────────────────────────────────────────
    args = parser.parse_args(argv)

    # Apply global flags
    if args.no_color or (hasattr(args, "scan_no_color") and args.scan_no_color):
        theme.set_no_color(True)

    if args.command is None:
        _cmd_no_args(parser)
        return

    try:
        if args.command == "start":
            _cmd_start(args)
        elif args.command == "version":
            _cmd_version()
        elif args.command == "scan":
            _cmd_scan(args)
        elif args.command == "signatures":
            _cmd_signatures(args)
        elif args.command == "init-hook":
            _cmd_init_hook(args)
    except KeyboardInterrupt:
        print(f"\n  {theme.dim('Interrupted. Exiting.')}")
        sys.exit(130)


# ── No-args handler: banner + guide + interactive menu ───────────────────

def _cmd_no_args(parser: argparse.ArgumentParser) -> None:
    """Called when user runs plain `reposcan` with no arguments.

    If stdout is a TTY: show banner, quick guide, and an interactive
    startup menu so first-time users can start a scan immediately.

    If stdout is NOT a TTY (piped/redirected): fall back to the old
    behaviour — banner + quick guide + help + exit 2.
    """
    print(theme.banner(__version__))
    print(theme.render_quick_guide())

    is_tty = False
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        pass

    if not is_tty:
        # Non-interactive context (e.g., piped to a file) — keep old behaviour
        parser.print_help()
        sys.exit(2)

    # ── Interactive startup menu ──────────────────────────────────────────
    menu_text = (
        "\n"
        "  ──────────────────────────────────────────────────────────────────\n"
        "  What would you like to do?\n\n"
        "    [1]  Safe scan of this folder  (recommended)\n"
        "    [2]  Scan a different folder\n"
        "    [3]  Just show the commands and exit\n\n"
        "  Enter choice (1/2/3, default 1): "
    )

    choice = None
    while choice not in ("1", "2", "3"):
        try:
            raw = input(menu_text).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {theme.dim('Exiting.')}")
            sys.exit(0)

        # Default to 1 on blank Enter
        if raw == "":
            choice = "1"
        elif raw in ("1", "2", "3"):
            choice = raw
        elif raw.lower() in ("q", "quit", "exit"):
            choice = "3"
        else:
            print(f"\n  {theme.dim('Please enter 1, 2, or 3.')}\n")

    if choice == "1":
        # Scan current folder — same as `reposcan start`
        print()
        _run_interactive_quickstart(".")

    elif choice == "2":
        # Ask for a path then scan it
        try:
            path_input = input(
                "\n  Enter the path you want to scan "
                "(or leave blank to cancel):\n  › "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {theme.dim('Cancelled. No scan was run.')}")
            sys.exit(0)

        if not path_input:
            print(f"\n  {theme.dim('Cancelled. No scan was run.')}")
            sys.exit(0)

        print()
        _run_interactive_quickstart(path_input)

    else:
        # choice == "3" — just show guide and exit
        print(f"\n  {theme.dim('Run  reposcan start  to scan this folder anytime.')}\n")
        sys.exit(0)


def _run_interactive_quickstart(target_path: str) -> None:
    """Run a full interactive scan for *target_path*.

    Shared by the startup menu (options 1 & 2) so there is no
    duplicated logic.  Prints welcome text, runs the loading view,
    prints the summary + findings, and shows the action menu if needed.
    Exits with the appropriate exit code.
    """
    print(theme.render_welcome_text(target_path))

    options = ScanOptions(interactive=True)

    try:
        result = _run_scan_with_loading(target_path, options, show_loading=True)
    except ScanError as exc:
        print(f"\n  {theme.error('✗ Error:')} {exc}\n", file=sys.stderr)
        sys.exit(2)

    # One-line plain-English status
    if result.critical_count > 0 or result.advisory_count > 0:
        print(f"  {theme.warning('Warning:')} RepoScan found suspicious files "
              f"in this folder. Read the summary below.\n")
    else:
        print(f"  {theme.success('Good news:')} RepoScan did not find anything "
              f"obviously dangerous in this folder.\n")

    # Summary + findings
    print(format_summary(result))
    findings_text = format_findings(result)
    if findings_text:
        print(findings_text)

    # Interactive action menu if there are actionable findings
    if has_actionable_findings(result.all_findings):
        if sys.stdout.isatty():
            run_action_menu(result.all_findings, result.target_path)
        else:
            print(f"  {theme.dim('Non-interactive terminal — skipping action menu.')}")
            print(f"  {theme.dim('Run with a TTY for interactive cleanup options.')}\n")

    sys.exit(compute_exit_code(result))


# ── Helper: run scan with optional loading view ──────────────────────────

def _run_scan_with_loading(
    target_path: str,
    options: ScanOptions,
    *,
    show_loading: bool = True,
):
    """Run a scan, optionally showing the branded loading screen.

    The loading screen is shown when:
      1. ``show_loading`` is True (non-JSON, TTY output).
      2. The terminal is a TTY (``sys.stdout.isatty()``).

    Returns the ScanResult.
    """
    # Decide if we can show the loading view
    is_tty = False
    try:
        is_tty = sys.stdout.isatty()
    except Exception:
        pass

    use_loading = show_loading and is_tty

    if use_loading:
        loading = LoadingView()
        loading.start()

        def on_progress(progress: ScanProgress) -> None:
            loading.update(progress)

        try:
            result = scan_with_progress(
                target_path, options, on_progress=on_progress,
            )
        except Exception:
            loading.finish()
            raise

        loading.finish()
    else:
        result = scan(target_path, options)

    return result


# ── Command handlers ─────────────────────────────────────────────────────

def _cmd_start(args: argparse.Namespace) -> None:
    """'reposcan start' — scan CWD interactively with the premium TUI."""
    print(theme.banner(__version__))
    _run_interactive_quickstart(".")


def _cmd_scan(args: argparse.Namespace) -> None:
    """'reposcan scan <path>' — scan with full options."""
    # Show banner for TTY output (unless JSON mode)
    if not args.json_output:
        print(theme.banner(__version__))
        print(theme.render_welcome_text(args.path))

    options = ScanOptions(
        no_ip_checks=args.no_ip_checks,
        fail_on_ip_risk=args.fail_on_ip_risk,
        json_output=args.json_output,
        signatures_dir=args.signatures_dir,
        exclude_patterns=args.exclude,
        follow_symlinks=args.follow_symlinks,
        interactive=args.interactive,
        no_heuristics=args.no_heuristics,
    )

    # Show loading screen unless --json
    show_loading = not args.json_output

    try:
        result = _run_scan_with_loading(
            args.path, options, show_loading=show_loading,
        )
    except ScanError as exc:
        if options.json_output:
            import json
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"\n  {theme.error('✗ Error:')} {exc}\n", file=sys.stderr)
        sys.exit(2)

    # Output
    if options.json_output:
        print(format_json(result))
    else:
        # One-line status
        if result.critical_count > 0 or result.advisory_count > 0:
            print(f"  {theme.warning('Warning:')} RepoScan found suspicious files "
                  f"in this folder. Read the summary below.\n")
        else:
            print(f"  {theme.success('Good news:')} RepoScan did not find anything "
                  f"obviously dangerous in this folder.\n")
        print(format_text(result))

    # Interactive menu (if --auto/--interactive and we have findings)
    if (
        options.interactive
        and not options.json_output
        and has_actionable_findings(result.all_findings)
    ):
        if sys.stdout.isatty():
            run_action_menu(result.all_findings, result.target_path)
        else:
            print(f"  {theme.dim('Non-interactive terminal — skipping action menu.')}\n")

    sys.exit(compute_exit_code(result, options.fail_on_ip_risk))


def _cmd_version() -> None:
    """'reposcan version' — show version + branding."""
    print(f"  RepoScan v{__version__} — THE ABOVE MINDSET")
    sys.exit(0)


def _cmd_signatures(args: argparse.Namespace) -> None:
    """'reposcan signatures' — show loaded signature database details."""
    print(theme.banner(__version__))

    custom_dir = getattr(args, "signatures_dir", None)

    try:
        db = load_signatures(custom_dir)
    except SignatureLoadError as exc:
        print(f"\n  {theme.error('✗ Error:')} {exc}\n", file=sys.stderr)
        sys.exit(2)

    print(theme.section_header("Loaded Signatures"))
    print()
    print(f"  {theme.bold('Malware signatures:')}   "
          f"{len(db.malware)}  (v{db.malware_version})")
    for sig in db.malware:
        print(f"    {theme.dim('•')} [{sig.id}] {sig.name}  "
              f"({sig.severity})")
    print()
    print(f"  {theme.bold('IP/leak-risk rules:')}   "
          f"{len(db.ip_leak_risk)}  (v{db.ip_leak_risk_version})")
    for ind in db.ip_leak_risk:
        print(f"    {theme.dim('•')} [{ind.id}] {ind.name}  "
              f"({ind.severity}, {ind.confidence} confidence)")
    print()
    print(f"  {theme.bold('Built-in heuristics:')}  4 rules (HEUR-001 … HEUR-004)")
    print()
    sys.exit(0)


def _cmd_init_hook(args: argparse.Namespace) -> None:
    """'reposcan init-hook' — install git hook."""
    from reposcan.hooks import install_hook, HookError
    try:
        path = install_hook(
            repo_path=".",
            hook_type=args.hook_type,
            force=args.force,
        )
        print(f"  {theme.success('✓')} Installed {args.hook_type} hook at: {path}")
        action = args.hook_type.replace("pre-", "")
        print(f"    The hook will run 'reposcan scan .' before each {action}.")
        print("    To bypass: git commit --no-verify")
    except HookError as exc:
        print(f"  {theme.error('✗ Error:')} {exc}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)
