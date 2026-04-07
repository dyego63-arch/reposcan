"""
Central theme module for RepoScan.

Provides ANSI color helpers, branded banner rendering, severity badges,
box-drawing utilities, styled print helpers, and the **LoadingView**
class that drives the branded scanning-progress screen.

Palette (from THE ABOVE MINDSET logo):
    GREEN  (#22c55e) — success / clean
    TEAL   (#06b6d4) — neutral info
    RED    (#f97373) — critical / danger
    AMBER  (#facc15) — advisory / warning
    WHITE  (#f9fafb) — main text
    BG     (#020617) — near-black background

Respects the ``NO_COLOR`` environment variable and ``--no-color`` flag.
"""

from __future__ import annotations

import os
import sys
import shutil
import time
from dataclasses import dataclass


# ── Global state ──────────────────────────────────────────────────────────

_no_color: bool = False


def set_no_color(value: bool) -> None:
    """Set the global no-color flag (called by CLI on ``--no-color``)."""
    global _no_color
    _no_color = value


def colors_enabled() -> bool:
    """Return True if colorized output is allowed."""
    if _no_color:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


# ── ANSI escape codes ─────────────────────────────────────────────────────
# We use 256-color / true-color where possible for the brand palette,
# but fall back to basic 16-color equivalents when wrapping raw text.

_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"

# Brand palette — 256-color approximations
# GREEN  #22c55e → 256-color index 77
# TEAL   #06b6d4 → 256-color index 38
# RED    #f97373 → 256-color index 210
# AMBER  #facc15 → 256-color index 220
# WHITE  #f9fafb → bright white (standard)

_GREEN_FG  = "\033[38;5;77m"
_TEAL_FG   = "\033[38;5;38m"
_RED_FG    = "\033[38;5;210m"
_AMBER_FG  = "\033[38;5;220m"
_WHITE_FG  = "\033[38;5;255m"

_GREEN_BG  = "\033[48;5;77m"
_TEAL_BG   = "\033[48;5;38m"
_RED_BG    = "\033[48;5;210m"
_AMBER_BG  = "\033[48;5;220m"
_DARK_BG   = "\033[48;5;233m"

# For the banner brand word
_BLACK_FG  = "\033[30m"
_BG_WHITE  = "\033[47m"

# Cursor control
_CURSOR_UP    = "\033[A"      # Move cursor up one line
_ERASE_LINE   = "\033[2K"     # Erase entire current line
_CURSOR_BOL   = "\r"          # Carriage return — move to beginning of line
_HIDE_CURSOR  = "\033[?25l"
_SHOW_CURSOR  = "\033[?25h"


def _wrap(code: str, text: str) -> str:
    if not colors_enabled():
        return text
    return f"{code}{text}{_RESET}"


# ── Public color primitives ───────────────────────────────────────────────

def green(text: str) -> str:
    """Brand green — success, clean."""
    return _wrap(f"{_BOLD}{_GREEN_FG}", text)


def teal(text: str) -> str:
    """Brand teal — neutral info."""
    return _wrap(f"{_BOLD}{_TEAL_FG}", text)


def red(text: str) -> str:
    """Brand red — critical danger."""
    return _wrap(f"{_BOLD}{_RED_FG}", text)


def amber(text: str) -> str:
    """Brand amber — advisory / warning."""
    return _wrap(f"{_BOLD}{_AMBER_FG}", text)


def yellow(text: str) -> str:
    """Alias for amber (backward compatibility)."""
    return amber(text)


def cyan(text: str) -> str:
    """Alias for teal (backward compatibility)."""
    return teal(text)


def bold(text: str) -> str:
    return _wrap(_BOLD, text)


def dim(text: str) -> str:
    return _wrap(_DIM, text)


def white(text: str) -> str:
    return _wrap(f"{_BOLD}{_WHITE_FG}", text)


# ── Semantic helpers (use these for meaning, not raw colors) ──────────────

def success(text: str) -> str:
    """Clean / safe / OK."""
    return green(text)


def info(text: str) -> str:
    """Neutral information."""
    return teal(text)


def warning(text: str) -> str:
    """Advisory / caution."""
    return amber(text)


def error(text: str) -> str:
    """Critical danger / failure."""
    return red(text)


# ── Severity badges ──────────────────────────────────────────────────────

_BADGE_MAP: dict[str, tuple[str, ...]] = {
    "CRITICAL_MALWARE": ("CRITICAL",  "red"),
    "CRITICAL":         ("CRITICAL",  "red"),
    "HIGH_RISK_LURE":   ("HIGH RISK", "amber"),
    "HIGH":             ("HIGH RISK", "amber"),
    "ADVISORY_IP_RISK": ("ADVISORY",  "teal"),
    "ADVISORY":         ("ADVISORY",  "teal"),
    "WARNING":          ("WARNING",   "amber"),
    "INFO":             ("INFO",      "dim"),
}

_COLOR_FNS = {
    "red": red, "amber": amber, "yellow": amber,
    "teal": teal, "cyan": teal,
    "dim": dim, "green": green, "white": white,
}


def severity_badge(severity: str) -> str:
    """Return a colored ``[SEVERITY]`` badge string."""
    entry = _BADGE_MAP.get(severity, ("UNKNOWN", "dim"))
    label, color_name = entry
    color_fn = _COLOR_FNS.get(color_name, dim)
    return color_fn(f"[{label}]")


# ── Banner ────────────────────────────────────────────────────────────────

# Big block-letter "REPOSCAN" — each letter is 6 chars wide, 6 lines tall.
# This gives us a massive, retro/terminal vibe banner.

_REPOSCAN_LETTERS = [
    # Line 0
    "██████╗ ███████╗██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗",
    # Line 1
    "██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║",
    # Line 2
    "██████╔╝█████╗  ██████╔╝██║   ██║███████╗██║     ███████║██╔██╗ ██║",
    # Line 3
    "██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║",
    # Line 4
    "██║  ██║███████╗██║     ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║",
    # Line 5
    "╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
]


def _get_terminal_width() -> int:
    """Get terminal width, default to 80."""
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def _color_bar(color_bg: str, width: int) -> str:
    """Return a colored bar of given width."""
    if not colors_enabled():
        return "█" * width
    return f"{color_bg}{' ' * width}{_RESET}"


def banner(version: str = "") -> str:
    """
    Render the god-tier branded RepoScan banner.

    Features:
    - Four vertical colored strips (green, teal, red, amber)
    - Massive block-letter REPOSCAN text
    - 'by THE ABOVE MINDSET' subtitle
    - Retro terminal vibe, dark background, minimal clutter
    """
    tw = _get_terminal_width()
    w = min(tw - 2, 78)  # Banner content width

    lines: list[str] = []
    lines.append("")

    if colors_enabled():
        # ── Color bar strip ──
        bar_w = max(w // 4, 10)
        bar_line = (
            f"{_GREEN_BG}{' ' * bar_w}{_RESET}"
            f"{_TEAL_BG}{' ' * bar_w}{_RESET}"
            f"{_RED_BG}{' ' * bar_w}{_RESET}"
            f"{_AMBER_BG}{' ' * bar_w}{_RESET}"
        )
        lines.append(f"  {bar_line}")
        lines.append("")

        # ── REPOSCAN block letters with color gradient ──
        bar_colors = [_GREEN_FG, _TEAL_FG, _RED_FG, _AMBER_FG]
        for i, letter_line in enumerate(_REPOSCAN_LETTERS):
            color = bar_colors[i % len(bar_colors)]
            centered = letter_line.center(w)
            lines.append(f"  {_BOLD}{color}{centered}{_RESET}")

        lines.append("")

        # ── Subtitle ──
        subtitle = "by  THE  ABOVE  MINDSET"
        sub_styled = (
            f"{_DIM}by  "
            f"{_RESET}{_BOLD}{_GREEN_FG}T{_TEAL_FG}H{_RED_FG}E{_RESET}  "
            f"{_BOLD}{_BG_WHITE}{_BLACK_FG} ABOVE {_RESET}  "
            f"{_BOLD}{_RED_FG}MIND{_AMBER_FG}SET{_RESET}"
        )
        # Rough center (visual length ~23 chars)
        pad = max(0, (w - 23) // 2)
        lines.append(f"  {' ' * pad}{sub_styled}")
        lines.append("")

        # ── Thin separator ──
        sep = f"{_DIM}{'─' * w}{_RESET}"
        lines.append(f"  {sep}")

        # ── Version + tagline ──
        if version:
            tag = f"v{version}  ·  Local-First Repo Safety Scanner"
            tag_styled = f"{_DIM}{tag.center(w)}{_RESET}"
            lines.append(f"  {tag_styled}")

        # ── Bottom color bar ──
        lines.append(f"  {bar_line}")
    else:
        # ── No-color fallback ──
        bar_line = "█" * w
        lines.append(f"  {bar_line}")
        lines.append("")

        for letter_line in _REPOSCAN_LETTERS:
            centered = letter_line.center(w)
            lines.append(f"  {centered}")

        lines.append("")
        lines.append(f"  {'by  THE  [ ABOVE ]  MINDSET'.center(w)}")
        lines.append("")
        lines.append(f"  {'─' * w}")

        if version:
            tag = f"v{version}  ·  Local-First Repo Safety Scanner"
            lines.append(f"  {tag.center(w)}")

        lines.append(f"  {bar_line}")

    lines.append("")
    return "\n".join(lines)


# ── Box-drawing / separators ─────────────────────────────────────────────

def separator(width: int = 58) -> str:
    """Heavy horizontal rule."""
    return "━" * width


def thin_separator(width: int = 58) -> str:
    """Light horizontal rule."""
    return "─" * width


def section_header(title: str) -> str:
    """Bold section title with underline."""
    return f"\n  {bold(title)}\n  {thin_separator(len(title) + 2)}"


# ── Prompts ───────────────────────────────────────────────────────────────

def prompt(message: str) -> str:
    """
    Read a line of user input with a colored prompt.

    Returns the stripped input string, or empty string at EOF.
    """
    try:
        return input(f"  {teal('›')} {message} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


# ── Styled print helpers ─────────────────────────────────────────────────

def print_success(msg: str) -> None:
    """Print a success message."""
    print(f"  {green('✓')} {msg}")


def print_error(msg: str) -> None:
    """Print an error message."""
    print(f"  {red('✗')} {msg}")


def print_warning(msg: str) -> None:
    """Print a warning message."""
    print(f"  {amber('⚠')} {msg}")


def print_info(msg: str) -> None:
    """Print an info message."""
    print(f"  {teal('ℹ')} {msg}")


# ── Quick Scan Guide ─────────────────────────────────────────────────────

def render_quick_guide() -> str:
    """Render the branded Quick Scan Guide block.

    Returns a multi-line string suitable for printing to a terminal.
    Uses bold + accent colors for labels and commands, normal weight
    for supporting text.  Falls back cleanly in ``--no-color`` mode.
    """
    lines: list[str] = []

    lines.append("")
    lines.append(f"  {bold('Quick guide')}")
    lines.append(f"  {thin_separator(12)}")
    lines.append("")

    # ── Scan this folder ──
    lines.append(f"  {teal('Scan this folder')}")
    lines.append(f"  Use {bold('reposcan start')} to scan the folder you are currently in.")
    lines.append("")

    # ── Scan a specific folder ──
    lines.append(f"  {teal('Scan a specific folder')}")
    _scan_cmd = 'reposcan scan "<path>"'
    lines.append(f"  Use {bold(_scan_cmd)} to scan a folder you choose.")
    _example_path = r'reposcan scan "C:\Users\YourName\Downloads"'
    lines.append(f"  Example: {bold(_example_path)}")
    lines.append("")

    # ── Scan an entire drive ──
    lines.append(f"  {teal('Scan an entire drive')} {dim('(advanced)')}")
    _drive_cmd = r"reposcan scan C:\ "
    lines.append(f"  Use {bold(_drive_cmd.rstrip())} to scan an entire drive.")
    lines.append(f"  This is an advanced option and may take longer on large drives.")
    lines.append("")

    return "\n".join(lines)


def quick_guide_plain() -> str:
    """Return the Quick Guide as plain text (for argparse help / epilog).

    This version uses no ANSI codes — suitable for piped output and
    the ``--help`` epilog rendered by argparse.
    """
    return (
        "\n"
        "Quick guide:\n"
        "\n"
        "  Scan this folder\n"
        "    reposcan start\n"
        "    Scans the folder you are currently in.\n"
        "\n"
        "  Scan a specific folder\n"
        '    reposcan scan "<path>"\n'
        '    Example: reposcan scan "C:\\Users\\YourName\\Downloads"\n'
        "\n"
        "  Scan an entire drive (advanced)\n"
        "    reposcan scan C:\\\n"
        "    May take longer on large drives.\n"
    )


# ── Loading View ─────────────────────────────────────────────────────────
#
# A branded, in-place loading screen shown while the scanner is working.
# Uses \r and ANSI cursor control to overwrite the same 4 lines:
#
#     Line 1: Slim 4-color brand bar (green/teal/red/amber)
#     Line 2: Progress bar + file count
#     Line 3: Running counters (critical / suspicious / advisory)
#     Line 4: Current file path being processed
#
# The view is driven by `LoadingView.update(progress)` calls from the CLI,
# which forward the ScanProgress snapshots emitted by scanner.py.

_SPINNER_CHARS = "|/-\\"            # Classic 4-frame spinner
_BAR_WIDTH = 30                     # Width of the progress bar in chars
_MIN_UPDATE_INTERVAL = 0.067        # ~15fps max update rate (seconds)


@dataclass
class _LoadingState:
    """Internal mutable state for the LoadingView."""
    lines_drawn: int = 0
    last_update: float = 0.0
    spinner_frame: int = 0
    started: bool = False
    finished: bool = False


class LoadingView:
    """Branded loading screen rendered in-place on a terminal.

    Usage::

        view = LoadingView()
        view.start()

        # During scan — called as a ScanProgress callback:
        view.update(progress)

        # When done:
        view.finish()
    """

    def __init__(self, *, output=None):
        self._out = output or sys.stdout
        self._state = _LoadingState()

    # ── Public API ────────────────────────────────────────────────────

    def start(self) -> None:
        """Print the initial "Scanning…" line and prepare the view."""
        if self._state.started:
            return
        self._state.started = True
        self._state.last_update = time.time()

        # Hide cursor for cleaner visual
        if colors_enabled():
            self._write(_HIDE_CURSOR)

        # Print initial blank lines that we will overwrite
        self._write_lines([
            self._render_brand_bar(),
            self._render_bar_line(0, 0, "Scanning files..."),
            self._render_counters(0, 0, 0),
            self._render_path("initializing..."),
        ])

    def update(self, progress) -> None:
        """Update the loading view from a ``ScanProgress`` snapshot.

        Throttled to ~15 fps to prevent flicker.
        """
        if self._state.finished:
            return

        now = time.time()
        # Throttle updates
        if now - self._state.last_update < _MIN_UPDATE_INTERVAL:
            return
        self._state.last_update = now
        self._state.spinner_frame += 1

        if not self._state.started:
            self.start()

        # Build the 4 display lines
        lines = [
            self._render_brand_bar(),
            self._render_bar_line(
                progress.files_processed,
                progress.total_estimate,
                "Scanning files...",
            ),
            self._render_counters(
                progress.critical_count,
                progress.suspicious_count,
                progress.advisory_count,
            ),
            self._render_path(progress.current_path),
        ]

        self._overwrite_lines(lines)

    def finish(self) -> None:
        """Stop the loading view and print the completion line."""
        if self._state.finished:
            return
        self._state.finished = True

        # Show cursor again
        if colors_enabled():
            self._write(_SHOW_CURSOR)

        # Clear the loading lines and print completion
        self._clear_lines()
        self._write(f"  {green('✓')} Scan complete. Preparing summary...\n\n")

    # ── Rendering helpers ─────────────────────────────────────────────

    def _render_brand_bar(self) -> str:
        """Slim 4-color bar echoing the banner."""
        tw = _get_terminal_width()
        w = min(tw - 4, 76)
        seg = max(w // 4, 4)

        if colors_enabled():
            return (
                f"  {_GREEN_BG}{' ' * seg}{_RESET}"
                f"{_TEAL_BG}{' ' * seg}{_RESET}"
                f"{_RED_BG}{' ' * seg}{_RESET}"
                f"{_AMBER_BG}{' ' * seg}{_RESET}"
            )
        else:
            return f"  {'=' * (seg * 4)}"

    def _render_bar_line(
        self, processed: int, total: int, label: str,
    ) -> str:
        """Render the progress bar line."""
        if total > 0:
            # Determinate mode: percentage bar
            pct = min(processed / total, 1.0)
            filled = int(pct * _BAR_WIDTH)
            empty = _BAR_WIDTH - filled

            if colors_enabled():
                # Gradient fill: green for first 50%, teal for rest
                green_w = min(filled, _BAR_WIDTH // 2)
                teal_w = filled - green_w
                bar = (
                    f"{_GREEN_BG}{' ' * green_w}{_RESET}"
                    f"{_TEAL_BG}{' ' * teal_w}{_RESET}"
                    f"{_DARK_BG}{' ' * empty}{_RESET}"
                )
                count_str = f"{_WHITE_FG}{processed:,}{_RESET} / {_DIM}{total:,}{_RESET}"
                return f"  {bar} {label} {count_str}"
            else:
                bar_fill = "#" * filled
                bar_empty = "." * empty
                return f"  [{bar_fill}{bar_empty}] {label} {processed:,} / {total:,}"
        else:
            # Indeterminate mode: spinner
            frame = _SPINNER_CHARS[self._state.spinner_frame % len(_SPINNER_CHARS)]

            if colors_enabled():
                spinner = f"{_BOLD}{_GREEN_FG}{frame}{_RESET}"
                count_str = f"{_WHITE_FG}{processed:,}{_RESET}"
                return f"  {spinner} {label} {count_str} files"
            else:
                return f"  {frame} {label} {processed:,} files"

    def _render_counters(
        self, critical: int, suspicious: int, advisory: int,
    ) -> str:
        """Render the running finding counters line."""
        if colors_enabled():
            c_val = f"{_RED_FG}{critical}{_RESET}" if critical else f"{_DIM}0{_RESET}"
            s_val = f"{_AMBER_FG}{suspicious}{_RESET}" if suspicious else f"{_DIM}0{_RESET}"
            a_val = f"{_TEAL_FG}{advisory}{_RESET}" if advisory else f"{_DIM}0{_RESET}"
            return (
                f"  {_DIM}Critical:{_RESET} {c_val}"
                f"  {_DIM}|{_RESET}  "
                f"{_DIM}Suspicious:{_RESET} {s_val}"
                f"  {_DIM}|{_RESET}  "
                f"{_DIM}Advisory:{_RESET} {a_val}"
            )
        else:
            return (
                f"  Critical: {critical}"
                f"  |  Suspicious: {suspicious}"
                f"  |  Advisory: {advisory}"
            )

    def _render_path(self, path: str) -> str:
        """Render the current-file-path line, truncated if needed."""
        tw = _get_terminal_width()
        max_path = tw - 20  # Leave room for prefix

        # Normalise separators
        display = path.replace("\\", "/")

        # Truncate from the left if too long
        if len(display) > max_path:
            display = "..." + display[-(max_path - 3):]

        # Prefix with ./
        if not display.startswith("./") and not display.startswith("..."):
            display = f"./{display}"

        if colors_enabled():
            return f"  {_DIM}Current: {display}{_RESET}"
        else:
            return f"  Current: {display}"

    # ── Terminal output helpers ───────────────────────────────────────

    def _write(self, text: str) -> None:
        """Write text to the output stream."""
        try:
            self._out.write(text)
            self._out.flush()
        except (OSError, UnicodeEncodeError):
            pass

    def _write_lines(self, lines: list[str]) -> None:
        """Write multiple lines, tracking how many we drew."""
        for line in lines:
            self._write(line + "\n")
        self._state.lines_drawn = len(lines)

    def _overwrite_lines(self, lines: list[str]) -> None:
        """Move cursor up and overwrite the previously drawn lines."""
        n = self._state.lines_drawn
        if n > 0:
            # Move up n lines
            if colors_enabled():
                self._write(f"\033[{n}A")
            else:
                # For no-cursor-control terminals, use \r per line
                self._write(_CURSOR_BOL + (f"\033[{n}A"))

        for line in lines:
            if colors_enabled():
                self._write(f"{_ERASE_LINE}{line}\n")
            else:
                # Pad with spaces to overwrite previous content
                tw = _get_terminal_width()
                padded = line.ljust(tw - 1)
                self._write(f"{_CURSOR_BOL}{padded}\n")

        self._state.lines_drawn = len(lines)

    def _clear_lines(self) -> None:
        """Clear the loading view lines."""
        n = self._state.lines_drawn
        if n > 0 and colors_enabled():
            self._write(f"\033[{n}A")
            for _ in range(n):
                self._write(f"{_ERASE_LINE}\n")
            self._write(f"\033[{n}A")
        elif n > 0:
            self._write(f"\033[{n}A")
            tw = _get_terminal_width()
            for _ in range(n):
                self._write(_CURSOR_BOL + " " * (tw - 1) + "\n")
            self._write(f"\033[{n}A")
        self._state.lines_drawn = 0

    # ── Static rendering for tests ────────────────────────────────────

    @staticmethod
    def render_bar_text(processed: int, total: int) -> str:
        """Render a plain-text progress bar string (for testing/no-color).

        Returns a string like ``[#####.....]  150 / 300``.
        """
        if total > 0:
            pct = min(processed / total, 1.0)
            filled = int(pct * _BAR_WIDTH)
            empty = _BAR_WIDTH - filled
            return f"[{'#' * filled}{'.' * empty}] {processed:,} / {total:,}"
        else:
            return f"[{'.' * _BAR_WIDTH}] {processed:,} / ?"

    @staticmethod
    def render_counters_text(
        critical: int, suspicious: int, advisory: int,
    ) -> str:
        """Render plain-text counters (for testing/no-color)."""
        return (
            f"Critical: {critical}"
            f"  |  Suspicious: {suspicious}"
            f"  |  Advisory: {advisory}"
        )
