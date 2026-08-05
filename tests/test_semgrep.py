"""
Purpose: Automated tests for the SemgrepScanner and SAST detection rules.

Responsibilities:
- Verify SAST rule detection for Python vulnerabilities (code injection, SQLi, unsafe deserialization, insecure hash).
- Verify SAST rule detection for JavaScript vulnerabilities (XSS via innerHTML, eval, secrets).
- Verify that SemgrepScanner directory traversal and detection works end-to-end.
- Verify that comment lines are correctly skipped.

Dependencies:
- pytest
- app.scanners.sast_rules.run_sast_scan
- app.scanners.semgrep.SemgrepScanner

Usage:
    pytest tests/test_semgrep.py -v
"""

import tempfile
from pathlib import Path
import pytest
from app.scanners.sast_rules import run_sast_scan
from app.scanners.semgrep import SemgrepScanner


# ─── Python SAST Rule Tests ─────────────────────────────────────────────────

def test_python_eval_detection():
    """Test detection of Python eval() code injection."""
    content = "result = eval(user_input)"
    findings = run_sast_scan(content, "main.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-code-injection-eval" in ids
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["line_number"] == 1


def test_python_exec_detection():
    """Test detection of Python exec() code injection."""
    content = "exec(compile(code, '<string>', 'exec'))"
    findings = run_sast_scan(content, "runner.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-code-injection-exec" in ids


def test_python_pickle_detection():
    """Test detection of unsafe pickle.loads() deserialization."""
    content = "data = pickle.loads(raw_bytes)"
    findings = run_sast_scan(content, "deserializer.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-unsafe-deserialization" in ids
    assert findings[0]["severity"] == "CRITICAL"


def test_python_yaml_load_detection():
    """Test detection of unsafe yaml.load() call."""
    content = "config = yaml.load(file_data)"
    findings = run_sast_scan(content, "config_loader.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-yaml-load" in ids


def test_python_insecure_random_detection():
    """Test detection of insecure random module usage."""
    content = "token = random.random()"
    findings = run_sast_scan(content, "auth.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-insecure-random" in ids
    assert findings[0]["severity"] == "MEDIUM"


def test_python_md5_detection():
    """Test detection of MD5 weak hashing algorithm."""
    content = "digest = hashlib.md5(data).hexdigest()"
    findings = run_sast_scan(content, "crypto.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-md5-sha1" in ids


def test_python_hardcoded_password():
    """Test detection of hardcoded password."""
    content = 'password = "Super$ecret123"'
    findings = run_sast_scan(content, "config.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-hardcoded-password" in ids


def test_python_subprocess_shell():
    """Test detection of subprocess with shell=True."""
    content = 'subprocess.run(cmd, shell=True)'
    findings = run_sast_scan(content, "runner.py")
    ids = [f["rule_id"] for f in findings]
    assert "python-subprocess-shell" in ids


def test_comment_lines_are_skipped():
    """Test that comment lines are not flagged."""
    content = "# eval(user_input)  -- this is a comment"
    findings = run_sast_scan(content, "notes.py")
    assert len(findings) == 0


def test_unsupported_extension_returns_no_findings():
    """Test that non-Python/JS files return empty findings."""
    content = "eval(user_input)"
    findings = run_sast_scan(content, "script.sh")
    assert len(findings) == 0


# ─── JavaScript SAST Rule Tests ─────────────────────────────────────────────

def test_js_eval_detection():
    """Test detection of JavaScript eval() code injection."""
    content = "const result = eval(userInput);"
    findings = run_sast_scan(content, "app.js")
    ids = [f["rule_id"] for f in findings]
    assert "js-code-injection-eval" in ids
    assert findings[0]["severity"] == "CRITICAL"


def test_js_innerhtml_xss_detection():
    """Test detection of XSS via innerHTML assignment."""
    content = "element.innerHTML = userInput;"
    findings = run_sast_scan(content, "ui.js")
    ids = [f["rule_id"] for f in findings]
    assert "js-xss-inner-html" in ids
    assert findings[0]["severity"] == "HIGH"


def test_js_document_write_detection():
    """Test detection of XSS via document.write()."""
    content = "document.write(location.search);"
    findings = run_sast_scan(content, "page.js")
    ids = [f["rule_id"] for f in findings]
    assert "js-xss-document-write" in ids


def test_js_settimeout_string_detection():
    """Test detection of string-based setTimeout (eval equivalent)."""
    content = 'setTimeout("doSomething()", 1000);'
    findings = run_sast_scan(content, "timer.js")
    ids = [f["rule_id"] for f in findings]
    assert "js-insecure-settimeout" in ids


def test_js_hardcoded_secret_detection():
    """Test detection of hardcoded API keys in JavaScript."""
    dummy_key = "sk_test_" + "abcdef123456"
    content = f'const apiKey = "{dummy_key}";'
    findings = run_sast_scan(content, "api.ts")
    ids = [f["rule_id"] for f in findings]
    assert "js-hardcoded-secret" in ids


# ─── SemgrepScanner Integration Tests ───────────────────────────────────────

@pytest.mark.asyncio
async def test_semgrep_scanner_native_engine():
    """Test SemgrepScanner end-to-end with native fallback engine."""
    scanner = SemgrepScanner()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Python file with eval injection
        py_file = temp_path / "exploit.py"
        py_file.write_text("result = eval(request.args.get('cmd'))\n")

        # JS file with XSS
        js_file = temp_path / "ui.js"
        js_file.write_text("document.getElementById('output').innerHTML = location.search;\n")

        # Non-supported file (should be skipped)
        md_file = temp_path / "README.md"
        md_file.write_text("# eval(bad_code) - just documentation")

        findings = await scanner.scan(temp_path)

        rule_ids = [f["rule_id"] for f in findings]
        assert "python-code-injection-eval" in rule_ids
        assert "js-xss-inner-html" in rule_ids
