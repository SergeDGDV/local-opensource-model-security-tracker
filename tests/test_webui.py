"""Static checks on the dashboard's inline JavaScript.

A parse error in one HTML file blanks the entire dashboard - no tiles, no tabs,
nothing - and every API test still passes, because the server is fine. That
happened once: Python-style implicit string concatenation across lines, which
JavaScript does not support. These checks make that class of mistake loud.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[1] / "src" / "lomst" / "webui" / "index.html"


def _script() -> str:
    html = UI.read_text()
    blocks = re.findall(r"<script>\n(.*?)\n</script>", html, re.S)
    assert blocks, "no inline <script> block found in index.html"
    return "\n".join(blocks)


def test_ui_file_exists_and_is_packaged():
    assert UI.exists()
    pyproject = (UI.resolve().parents[3] / "pyproject.toml").read_text()
    assert "webui/*.html" in pyproject, "the UI must be listed as package data"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_inline_javascript_parses(tmp_path):
    js = tmp_path / "app.js"
    js.write_text(_script())
    result = subprocess.run(
        ["node", "--check", str(js)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, f"dashboard JS does not parse:\n{result.stderr}"


def test_no_adjacent_string_literals():
    """Catch the Python habit that broke it, even without node available."""
    offenders = []
    for lineno, line in enumerate(_script().splitlines(), 1):
        stripped = line.strip()
        # a line that is purely a quoted string, not joined by + or , or (
        if re.fullmatch(r'"[^"]*"', stripped) or re.fullmatch(r"'[^']*'", stripped):
            offenders.append((lineno, stripped[:60]))
    assert not offenders, (
        "these lines are bare string literals, which in JS means the previous line "
        f"is missing a '+': {offenders}"
    )


def test_status_colours_are_paired_with_icon_and_label():
    """The status palette is sub-3:1 on the light surface by design, so colour
    must never carry meaning alone."""
    js = _script()
    for mapping in ("URGENCY", "VERDICT", "SEVERITY", "STATUS", "LIFECYCLE", "TIER"):
        assert f"const {mapping} = {{" in js, mapping
    # every entry in those maps carries both `ic:` and `label:`
    for block in re.findall(r"const (?:URGENCY|VERDICT|SEVERITY|STATUS|LIFECYCLE|TIER) = \{(.*?)\n\};", js, re.S):
        for entry in re.findall(r"\{[^{}]*\}", block):
            assert "ic:" in entry and "label:" in entry, entry


def test_dark_mode_is_declared_under_both_scopes():
    """The OS media query and the explicit toggle must both work."""
    html = UI.read_text()
    assert "@media (prefers-color-scheme: dark)" in html
    assert ':root[data-theme="dark"]' in html
    assert ':root:where(:not([data-theme="light"]))' in html
