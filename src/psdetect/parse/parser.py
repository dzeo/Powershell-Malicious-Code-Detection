"""Parser interface for PowerShell-like commands.

This module provides a dependency-free fallback parser and a backend selection
layer. When `pwsh` becomes available, the same interface can be upgraded to a
native AST-backed implementation without changing feature extraction code.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_\-\.:\[\]]*|\$[A-Za-z_][A-Za-z0-9_]*|-[A-Za-z][A-Za-z0-9\-]*")
CMDLET_RE = re.compile(r"\b[A-Za-z]+-[A-Za-z][A-Za-z0-9]+\b")
PARAM_RE = re.compile(r"(?<!\w)(-[A-Za-z][A-Za-z0-9\-]*)")

ALIAS_TO_COMMAND = {
    "iex": "Invoke-Expression",
    "iwr": "Invoke-WebRequest",
    "curl": "Invoke-WebRequest",
    "wget": "Invoke-WebRequest",
    "ls": "Get-ChildItem",
    "gc": "Get-Content",
    "cat": "Get-Content",
    "sc": "Set-Content",
    "sv": "Set-Variable",
    "gv": "Get-Variable",
    "ni": "New-Item",
}

KEYWORD_PATTERNS = {
    "has_if": r"(?i)\bif\b",
    "has_foreach": r"(?i)\bforeach\b",
    "has_function": r"(?i)\bfunction\b",
    "has_try": r"(?i)\btry\b",
    "has_catch": r"(?i)\bcatch\b",
    "has_scriptblock": r"[{}]",
    "has_pipeline": r"\|",
    "has_dotnet": r"(?i)\[[A-Za-z0-9_.]+\]",
    "has_reflection": r"(?i)\[reflection\.|assembly::load",
    "has_new_object": r"(?i)\bnew-object\b",
    "has_invoke_expression": r"(?i)\binvoke-expression\b|\biex\b",
}


@dataclass
class ParseArtifacts:
    tokens: list[str]
    commands: list[str]
    parameters: list[str]
    aliases: list[str]
    ast_like_counts: dict[str, int] = field(default_factory=dict)
    parse_quality: dict[str, int | float] = field(default_factory=dict)
    backend: str = "fallback"


def _fallback_parse_text(text: str) -> ParseArtifacts:
    tokens = TOKEN_RE.findall(text)
    lower_tokens = [token.lower() for token in tokens]

    commands = []
    for match in CMDLET_RE.finditer(text):
        commands.append(match.group(0))

    aliases = [tok for tok in lower_tokens if tok in ALIAS_TO_COMMAND]
    parameters = [match.group(1) for match in PARAM_RE.finditer(text)]
    ast_like_counts = {name: int(bool(re.search(pattern, text))) for name, pattern in KEYWORD_PATTERNS.items()}

    ast_like_counts.update(
        {
            "brace_open_count": text.count("{"),
            "brace_close_count": text.count("}"),
            "paren_open_count": text.count("("),
            "paren_close_count": text.count(")"),
            "bracket_open_count": text.count("["),
            "bracket_close_count": text.count("]"),
            "variable_count": len(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", text)),
            "assignment_count": len(re.findall(r"(?<![=!<>])=(?!=)", text)),
            "cmdlet_count": len(commands),
            "parameter_count": len(parameters),
            "alias_count": len(aliases),
        }
    )

    quote_imbalance = _quote_balance(text, "'") + _quote_balance(text, '"')
    structure_mismatch = (
        abs(ast_like_counts["brace_open_count"] - ast_like_counts["brace_close_count"])
        + abs(ast_like_counts["paren_open_count"] - ast_like_counts["paren_close_count"])
        + abs(ast_like_counts["bracket_open_count"] - ast_like_counts["bracket_close_count"])
    )

    token_histogram = Counter(token.lower() for token in commands)
    parse_quality = {
        "quote_imbalance": quote_imbalance,
        "structure_mismatch": structure_mismatch,
        "unique_command_count": len(token_histogram),
        "unique_parameter_count": len(set(param.lower() for param in parameters)),
    }

    return ParseArtifacts(
        tokens=tokens,
        commands=commands,
        parameters=parameters,
        aliases=aliases,
        ast_like_counts=ast_like_counts,
        parse_quality=parse_quality,
        backend="fallback",
    )


def _pwsh_binary() -> str | None:
    for name in ("pwsh", "powershell"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _native_parse_text(text: str) -> ParseArtifacts | None:
    binary = _pwsh_binary()
    if binary is None:
        return None

    ps_script = r"""
$inputText = @'
__PAYLOAD__
'@
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($inputText, [ref]$tokens, [ref]$errors)
$commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
    $_.GetCommandName()
} | Where-Object { $_ })
$params = @($tokens | Where-Object { $_.Kind -eq 'Parameter' } | ForEach-Object { $_.Text })
$payload = [ordered]@{
    tokens = @($tokens | ForEach-Object { $_.Text })
    commands = $commands
    parameters = $params
    aliases = @()
    ast_like_counts = [ordered]@{
        cmdlet_count = $commands.Count
        parameter_count = $params.Count
        parse_error_count = @($errors).Count
    }
    parse_quality = [ordered]@{
        quote_imbalance = 0
        structure_mismatch = 0
        unique_command_count = @($commands | Select-Object -Unique).Count
        unique_parameter_count = @($params | Select-Object -Unique).Count
    }
    backend = 'pwsh_native'
}
$payload | ConvertTo-Json -Depth 6 -Compress
"""
    ps_script = ps_script.replace("__PAYLOAD__", text.replace("'", "''"))

    try:
        result = subprocess.run(
            [binary, "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return None

    return ParseArtifacts(
        tokens=list(payload.get("tokens", [])),
        commands=list(payload.get("commands", [])),
        parameters=list(payload.get("parameters", [])),
        aliases=list(payload.get("aliases", [])),
        ast_like_counts=dict(payload.get("ast_like_counts", {})),
        parse_quality=dict(payload.get("parse_quality", {})),
        backend=str(payload.get("backend", "pwsh_native")),
    )


def _quote_balance(text: str, quote: str) -> int:
    return text.count(quote) % 2


def parse_text(text: str, backend: str = "auto") -> ParseArtifacts:
    if backend not in {"auto", "fallback", "native"}:
        raise ValueError(f"Unsupported parser backend: {backend}")

    if backend in {"auto", "native"}:
        native = _native_parse_text(text)
        if native is not None:
            return native
        if backend == "native":
            raise RuntimeError("Native PowerShell parser backend is unavailable.")

    return _fallback_parse_text(text)
