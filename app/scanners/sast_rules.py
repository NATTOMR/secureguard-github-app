"""
Purpose: SAST rule definitions for Python and JavaScript vulnerability detection.

Responsibilities:
- Define structured SAST rules mapped to OWASP Top 10 categories.
- Provide a native Python fallback SAST scanning engine using regex pattern matching.
- Detect insecure code patterns including SQLi, XSS, code injection, unsafe deserialization,
  hardcoded credentials, path traversal, and insecure cryptography.

Dependencies:
- re

Usage:
    from app.scanners.sast_rules import run_sast_scan

    findings = run_sast_scan("file_content", "path/to/file.py")
"""

import re
from typing import Any, Dict, List

# OWASP Top 10 SAST Rules — Python
PYTHON_RULES: List[Dict[str, Any]] = [
    {
        "id": "python-code-injection-eval",
        "title": "Code Injection via eval()",
        "owasp": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "regex": re.compile(r"\beval\s*\("),
        "description": "Use of eval() can execute arbitrary code if input is user-controlled.",
        "recommendation": "Replace eval() with safer alternatives such as ast.literal_eval() for data parsing.",
        "language": "python",
    },
    {
        "id": "python-code-injection-exec",
        "title": "Code Injection via exec()",
        "owasp": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bexec\s*\("),
        "description": "Use of exec() can execute arbitrary code if input is user-controlled.",
        "recommendation": "Avoid exec(). Use importlib or defined function calls instead.",
        "language": "python",
    },
    {
        "id": "python-sql-injection",
        "title": "Potential SQL Injection",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "regex": re.compile(r'(execute|cursor\.execute)\s*\(\s*["\'].*(%s|%d|\+|f"|f\')'),
        "description": "SQL query constructed with string formatting is susceptible to SQL Injection.",
        "recommendation": "Use parameterized queries or ORM methods. Never concatenate user input into SQL.",
        "language": "python",
    },
    {
        "id": "python-unsafe-deserialization",
        "title": "Unsafe Deserialization via pickle",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "CRITICAL",
        "regex": re.compile(r"\bpickle\s*\.\s*(loads|load)\s*\("),
        "description": "pickle.loads() can execute arbitrary code when deserializing untrusted data.",
        "recommendation": "Replace pickle with JSON or MessagePack for serialization of untrusted data.",
        "language": "python",
    },
    {
        "id": "python-yaml-load",
        "title": "Unsafe YAML Loading",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "HIGH",
        "regex": re.compile(r"\byaml\s*\.\s*load\s*\("),
        "description": "yaml.load() can execute arbitrary Python objects embedded in YAML.",
        "recommendation": "Use yaml.safe_load() instead of yaml.load().",
        "language": "python",
    },
    {
        "id": "python-path-traversal",
        "title": "Potential Path Traversal",
        "owasp": "A01:2021 - Broken Access Control",
        "severity": "HIGH",
        "regex": re.compile(r'open\s*\(\s*(request\.|f"|f\'|str\(|os\.path\.join)'),
        "description": "File open with user-controlled path may allow directory traversal attacks.",
        "recommendation": "Validate and sanitize file paths. Use pathlib.resolve() and check against an allowed base directory.",
        "language": "python",
    },
    {
        "id": "python-insecure-random",
        "title": "Insecure Random Number Generation",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "MEDIUM",
        "regex": re.compile(r"\brandom\s*\.\s*(random|randint|choice|shuffle)\s*\("),
        "description": "The random module is not cryptographically secure.",
        "recommendation": "Use secrets module or os.urandom() for generating cryptographic tokens.",
        "language": "python",
    },
    {
        "id": "python-md5-sha1",
        "title": "Use of Weak Hashing Algorithm (MD5/SHA1)",
        "owasp": "A02:2021 - Cryptographic Failures",
        "severity": "MEDIUM",
        "regex": re.compile(r'hashlib\s*\.\s*(md5|sha1)\s*\('),
        "description": "MD5 and SHA1 are cryptographically broken and should not be used for security.",
        "recommendation": "Use hashlib.sha256() or hashlib.sha3_256() for secure hashing.",
        "language": "python",
    },
    {
        "id": "python-hardcoded-password",
        "title": "Hardcoded Password or Secret",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(password|passwd|secret|token)\s*=\s*["\'][^"\']{4,}["\']'),
        "description": "Hardcoded credentials detected in source code.",
        "recommendation": "Store secrets in environment variables or a secrets management system. Never hardcode credentials.",
        "language": "python",
    },
    {
        "id": "python-subprocess-shell",
        "title": "Shell Injection via subprocess",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "regex": re.compile(r'subprocess\.(run|call|Popen).*shell\s*=\s*True'),
        "description": "subprocess with shell=True is vulnerable to OS command injection.",
        "recommendation": "Pass commands as a list instead of a string and set shell=False.",
        "language": "python",
    },
]

# OWASP Top 10 SAST Rules — JavaScript
JAVASCRIPT_RULES: List[Dict[str, Any]] = [
    {
        "id": "js-code-injection-eval",
        "title": "Code Injection via eval()",
        "owasp": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "regex": re.compile(r"\beval\s*\("),
        "description": "Use of eval() with user-controlled input can execute arbitrary JavaScript.",
        "recommendation": "Avoid eval(). Use JSON.parse() for data or explicitly define function calls.",
        "language": "javascript",
    },
    {
        "id": "js-xss-inner-html",
        "title": "Cross-Site Scripting (XSS) via innerHTML",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "regex": re.compile(r"\.innerHTML\s*=\s*(?!(['\"`]<))"),
        "description": "Setting innerHTML with user-controlled data allows Cross-Site Scripting attacks.",
        "recommendation": "Use textContent or sanitize HTML with DOMPurify before assigning to innerHTML.",
        "language": "javascript",
    },
    {
        "id": "js-xss-document-write",
        "title": "Cross-Site Scripting (XSS) via document.write()",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "regex": re.compile(r"\bdocument\.write\s*\("),
        "description": "document.write() with user input can lead to XSS vulnerabilities.",
        "recommendation": "Avoid document.write(). Use DOM manipulation APIs or a templating engine with auto-escaping.",
        "language": "javascript",
    },
    {
        "id": "js-insecure-settimeout",
        "title": "Code Injection via setTimeout/setInterval with string",
        "owasp": "A03:2021 - Injection",
        "severity": "HIGH",
        "regex": re.compile(r'\b(setTimeout|setInterval)\s*\(\s*["\']'),
        "description": "Passing a string to setTimeout/setInterval is equivalent to using eval().",
        "recommendation": "Always pass a function reference, not a string, to setTimeout/setInterval.",
        "language": "javascript",
    },
    {
        "id": "js-hardcoded-secret",
        "title": "Hardcoded Secret in JavaScript",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "severity": "HIGH",
        "regex": re.compile(r'(?i)(password|secret|apikey|api_key|token)\s*[:=]\s*["\'][^"\']{4,}["\']'),
        "description": "Hardcoded secrets exposed in JavaScript source can be extracted from browser.",
        "recommendation": "Never embed credentials in client-side JavaScript. Use server-side sessions.",
        "language": "javascript",
    },
    {
        "id": "js-prototype-pollution",
        "title": "Prototype Pollution Risk",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "severity": "MEDIUM",
        "regex": re.compile(r'__proto__|constructor\s*\['),
        "description": "Prototype pollution can corrupt the JavaScript object prototype chain.",
        "recommendation": "Use Object.create(null) for safe object creation without prototype chain.",
        "language": "javascript",
    },
]

# File extension to language mapping
EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
}


def run_sast_scan(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Scan file content using SAST rules for the detected language and return findings."""
    findings: List[Dict[str, Any]] = []

    # Determine language from file extension
    extension = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    language = EXTENSION_TO_LANGUAGE.get(extension)
    if not language:
        return findings

    rule_set = PYTHON_RULES if language == "python" else JAVASCRIPT_RULES

    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        for rule in rule_set:
            if rule["regex"].search(line):
                findings.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "file_path": file_path,
                    "line_number": i + 1,
                    "description": f"[{rule['owasp']}] {rule['description']}",
                    "recommendation": rule["recommendation"],
                    "scanner_name": "SecureGuard-SAST",
                })
    return findings
