"""Static checks for MCP `tools/list` JSON. Standard library only, no network."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict

ERROR, WARN, INFO = "error", "warn", "info"

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"do not (tell|inform|mention)[^.]{0,40}\buser\b",
    r"don'?t (tell|inform|mention)[^.]{0,40}\buser\b",
    r"<\s*important\s*>",
    r"\bsystem prompt\b",
    r"\bexfiltrat",
]
HIDDEN_CHARS = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
SECRET_PATTERNS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", "API key (sk-...)"),
    (r"\bghp_[A-Za-z0-9]{30,}\b", "GitHub token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
]
DANGEROUS_NAME = re.compile(
    r"(delete|drop|remove|exec|shell|run|write|send|transfer|pay|deploy|kill|truncate)", re.I
)
FREEFORM_PARAMS = {"command", "cmd", "sql", "query", "path", "file", "url", "code", "script"}
MAX_DESCRIPTION = 1000


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def _texts(tool: dict):
    """Yield (where, text) for every description-like string in a tool."""
    if isinstance(tool.get("description"), str):
        yield "description", tool["description"]
    for pname, p in ((tool.get("inputSchema") or {}).get("properties") or {}).items():
        if isinstance(p, dict):
            if isinstance(p.get("description"), str):
                yield f"param '{pname}' description", p["description"]
            if isinstance(p.get("default"), str):
                yield f"param '{pname}' default", p["default"]


def audit_tool(tool: dict) -> list[Finding]:
    name = str(tool.get("name", "")) or "<unnamed>"
    out: list[Finding] = []

    def add(rule, sev, msg):
        out.append(Finding(name, rule, sev, msg))

    if not tool.get("name"):
        add("missing-name", ERROR, "Tool has no name.")
    desc = tool.get("description")
    if not isinstance(desc, str) or not desc.strip():
        add("missing-description", WARN, "No description. The model cannot tell when to use this tool.")
    elif len(desc) > MAX_DESCRIPTION:
        add("long-description", INFO, f"Description is {len(desc)} characters (over {MAX_DESCRIPTION}).")

    for where, text in _texts(tool):
        for pat in INJECTION_PATTERNS:
            if re.search(pat, text, re.I):
                add("prompt-injection-phrase", ERROR,
                    f"{where}: text looks like an instruction aimed at the model.")
                break
        if HIDDEN_CHARS.search(text):
            add("hidden-characters", ERROR, f"{where}: contains invisible or bidirectional characters.")
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, text):
                add("secret-in-definition", ERROR, f"{where}: looks like a {label}.")

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        add("missing-input-schema", WARN, "No inputSchema.")
        schema = {}
    elif schema.get("additionalProperties") is not False:
        add("open-schema", INFO, "inputSchema does not set additionalProperties to false.")

    ann = tool.get("annotations") or {}
    if DANGEROUS_NAME.search(name) and not any(k in ann for k in ("readOnlyHint", "destructiveHint")):
        add("missing-annotations", WARN,
            "Name suggests a side effect, but there is no readOnlyHint or destructiveHint.")
    if ann.get("readOnlyHint") is True and ann.get("destructiveHint") is True:
        add("contradictory-annotations", ERROR, "readOnlyHint and destructiveHint are both true.")

    props = schema.get("properties") or {}
    for pname, p in props.items():
        if not isinstance(p, dict) or p.get("type") != "string":
            continue
        bounded = any(k in p for k in ("enum", "pattern", "maxLength", "format", "const"))
        if pname.lower() in FREEFORM_PARAMS and not bounded:
            add("unbounded-freeform-param", WARN,
                f"Param '{pname}' is a free string with no enum, pattern or maxLength.")
    for req in schema.get("required") or []:
        if req not in props:
            add("required-not-defined", WARN, f"'{req}' is required but not in properties.")
    return out


def audit(doc) -> list[Finding]:
    """Audit a parsed `tools/list` result: {"tools": [...]} or a bare list."""
    tools = doc.get("tools") if isinstance(doc, dict) else doc
    if not isinstance(tools, list):
        raise ValueError('Expected {"tools": [...]} or a list of tools.')
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for t in tools:
        if not isinstance(t, dict):
            raise ValueError("Every tool must be a JSON object.")
        findings += audit_tool(t)
        n = str(t.get("name", ""))
        seen[n] = seen.get(n, 0) + 1
    for n, c in seen.items():
        if c > 1 and n:
            findings.append(Finding(n, "duplicate-name", ERROR, f"Tool name appears {c} times."))
    return findings


def load(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
