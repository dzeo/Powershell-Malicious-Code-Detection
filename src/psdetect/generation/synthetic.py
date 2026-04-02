"""Safe synthetic PowerShell-like sample generation.

The suspicious samples generated here are non-operational surrogates intended for
pipeline testing, parser hardening, and regression evaluation. They are designed
to resemble malicious patterns lexically and structurally without shipping a real
payload or live attack chain.
"""

from __future__ import annotations

import base64
import csv
import json
import random
import string
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from tqdm.auto import tqdm

from psdetect.logging_utils import logger

BENIGN_FOLDERS = [
    r"C:\Ops\Scripts",
    r"C:\ProgramData\Backups",
    r"C:\Logs",
    r"D:\Automation",
    r"C:\Temp",
]

BENIGN_FILES = [
    "CollectInventory.ps1",
    "RotateLogs.ps1",
    "ArchiveReports.ps1",
    "SyncShares.ps1",
    "CheckServices.ps1",
]

BENIGN_SERVICES = [
    "Spooler",
    "WinRM",
    "Dnscache",
    "W32Time",
    "BITS",
]

SAFE_DOMAINS = [
    "example.invalid",
    "test.invalid",
    "corp.example",
]

REGISTRY_KEYS = [
    r"HKCU:\Software\Contoso\Run",
    r"HKLM:\Software\ExampleCorp\Policies",
]


@dataclass(frozen=True)
class SyntheticSample:
    sample_id: str
    label: str
    family: str
    text: str
    safe_surrogate: bool = True


def _rand_word(rng: random.Random, min_len: int = 4, max_len: int = 10) -> str:
    size = rng.randint(min_len, max_len)
    return "".join(rng.choice(string.ascii_letters) for _ in range(size))


def _rand_identifier(rng: random.Random) -> str:
    parts = [_rand_word(rng, 3, 8) for _ in range(rng.randint(2, 4))]
    return "_".join(parts)


def _rand_path(rng: random.Random) -> str:
    return rf"{rng.choice(BENIGN_FOLDERS)}\{rng.choice(BENIGN_FILES)}"


def _rand_url(rng: random.Random, path_name: str) -> str:
    return f"https://{rng.choice(SAFE_DOMAINS)}/{path_name}"


def _safe_encoded_command(rng: random.Random) -> str:
    harmless = (
        "Write-Output 'SIMULATED ENCODED COMMAND'; "
        f"$marker = '{_rand_identifier(rng)}'; "
        "Start-Sleep -Milliseconds 1"
    )
    encoded = base64.b64encode(harmless.encode("utf-16-le")).decode("ascii")
    return (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded}"
    )


def _safe_hex_blob(rng: random.Random) -> str:
    marker = f"SIMULATED_HEX_{_rand_identifier(rng)}".encode("utf-8").hex()
    return (
        "$blob = '"
        + marker
        + "'; Write-Output 'SIMULATED HEX PAYLOAD'; Write-Output $blob.Length"
    )


def _benign_templates(rng: random.Random) -> list[tuple[str, str]]:
    src = _rand_path(rng)
    dst = _rand_path(rng)
    service = rng.choice(BENIGN_SERVICES)
    report = rf"C:\Reports\{_rand_identifier(rng)}.csv"
    url = f"https://intranet.{rng.choice(['corp.local', 'example.com'])}/health"
    key = rng.choice(REGISTRY_KEYS)
    return [
        (
            "benign_inventory",
            (
                f"Get-ChildItem -Path '{src}' -Recurse | "
                "Select-Object FullName, Length, LastWriteTime"
            ),
        ),
        (
            "benign_backup",
            f"Copy-Item -Path '{src}' -Destination '{dst}' -Force",
        ),
        (
            "benign_service_check",
            (
                f"Get-Service -Name '{service}' | "
                "Select-Object Name, Status, StartType"
            ),
        ),
        (
            "benign_report_export",
            (
                "Get-Process | Select-Object ProcessName, Id, CPU | "
                f"Export-Csv -NoTypeInformation -Path '{report}'"
            ),
        ),
        (
            "benign_healthcheck",
            f"Invoke-WebRequest -Uri '{url}' -UseBasicParsing | Select-Object StatusCode",
        ),
        (
            "benign_registry_read",
            f"Get-ItemProperty -Path '{key}' | Select-Object *",
        ),
    ]


def _suspicious_surrogate_templates(rng: random.Random) -> list[tuple[str, str]]:
    url = _rand_url(rng, "payload.txt")
    temp_path = rf"$env:TEMP\{_rand_identifier(rng)}.ps1"
    command_name = "'In'+'voke-Expression'"
    obfuscated = "'Do'+'wn'+'load'+'String'"
    return [
        (
            "surrogate_encoded_command",
            _safe_encoded_command(rng),
        ),
        (
            "surrogate_hidden_runner",
            (
                "powershell.exe -WindowStyle Hidden -NoProfile -Command "
                "\"Write-Output 'SIMULATED HIDDEN EXECUTION'; "
                "$note = 'simulation-only';\""
            ),
        ),
        (
            "surrogate_download_chain",
            (
                f"$url = '{url}'; $dst = '{temp_path}'; "
                "Write-Output 'SIMULATED download and execution chain'; "
                "Write-Output $url; Write-Output $dst"
            ),
        ),
        (
            "surrogate_obfuscated_strings",
            (
                f"$cmd = {command_name}; $net = {obfuscated}; "
                "Write-Output 'SIMULATED OBFUSCATION'; Write-Output $cmd; Write-Output $net"
            ),
        ),
        (
            "surrogate_amsi_reference",
            (
                "$message = 'SIMULATED AMSI BYPASS REFERENCE'; "
                "Write-Output $message; "
                "Write-Output 'System.Management.Automation'"
            ),
        ),
        (
            "surrogate_registry_persistence",
            (
                "Write-Output 'SIMULATED RUN KEY PERSISTENCE'; "
                f"Write-Output \"Set-ItemProperty -Path '{rng.choice(REGISTRY_KEYS)}' -Name demo -Value simulated\""
            ),
        ),
        (
            "surrogate_reflection_reference",
            (
                "Write-Output 'SIMULATED REFLECTION LOAD'; "
                "Write-Output '[Reflection.Assembly]::Load'"
            ),
        ),
        (
            "surrogate_hex_blob",
            _safe_hex_blob(rng),
        ),
    ]


def generate_dataset(
    total: int,
    benign_ratio: float = 0.6,
    seed: int = 42,
    show_progress: bool = False,
    log_every: int = 10000,
) -> list[SyntheticSample]:
    if total <= 0:
        raise ValueError("total must be positive")
    if not 0.0 <= benign_ratio <= 1.0:
        raise ValueError("benign_ratio must be between 0 and 1")

    rng = random.Random(seed)
    benign_total = int(total * benign_ratio)
    suspicious_total = total - benign_total
    samples: list[SyntheticSample] = []

    logger.info(
        "Generating synthetic dataset: total={}, benign_total={}, suspicious_total={}, seed={}",
        total,
        benign_total,
        suspicious_total,
        seed,
    )

    benign_iter = range(benign_total)
    if show_progress:
        benign_iter = tqdm(benign_iter, total=benign_total, desc="Generating benign samples")

    for idx in benign_iter:
        family, text = rng.choice(_benign_templates(rng))
        samples.append(
            SyntheticSample(
                sample_id=f"syn-benign-{idx:07d}",
                label="benign",
                family=family,
                text=text,
            )
        )
        if log_every and (idx + 1) % log_every == 0:
            logger.debug("Generated {} benign samples so far", idx + 1)

    suspicious_iter = range(suspicious_total)
    if show_progress:
        suspicious_iter = tqdm(
            suspicious_iter,
            total=suspicious_total,
            desc="Generating suspicious surrogate samples",
        )

    for idx in suspicious_iter:
        family, text = rng.choice(_suspicious_surrogate_templates(rng))
        samples.append(
            SyntheticSample(
                sample_id=f"syn-suspicious-{idx:07d}",
                label="suspicious_surrogate",
                family=family,
                text=text,
            )
        )
        if log_every and (idx + 1) % log_every == 0:
            logger.debug("Generated {} suspicious surrogate samples so far", idx + 1)

    rng.shuffle(samples)
    logger.info("Completed synthetic dataset generation with {} rows", len(samples))
    return samples


def write_jsonl(
    samples: Iterable[SyntheticSample],
    output_path: Path,
    *,
    show_progress: bool = False,
    total: int | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Writing JSONL dataset to {}", output_path)
    iterable = samples
    if show_progress:
        iterable = tqdm(samples, total=total, desc="Writing JSONL")
    with output_path.open("w", encoding="utf-8") as handle:
        for sample in iterable:
            handle.write(json.dumps(asdict(sample), ensure_ascii=True) + "\n")
    logger.info("Finished writing JSONL dataset to {}", output_path)


def write_csv(
    samples: Iterable[SyntheticSample],
    output_path: Path,
    *,
    show_progress: bool = False,
    total: int | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["sample_id", "label", "family", "text", "safe_surrogate"]
    logger.info("Writing CSV dataset to {}", output_path)
    iterable = samples
    if show_progress:
        iterable = tqdm(samples, total=total, desc="Writing CSV")
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for sample in iterable:
            writer.writerow(asdict(sample))
    logger.info("Finished writing CSV dataset to {}", output_path)
