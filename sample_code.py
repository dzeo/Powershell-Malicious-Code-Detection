"""
Unsupervised Malicious PowerShell Detection Pipeline
=====================================================
Approach: Multi-feature extraction → Normalization → 
          Autoencoder (anomaly scoring) + DBSCAN/UMAP clustering
No labels required.
"""

import re
import math
import base64
import numpy as np
import pandas as pd
from collections import Counter

# ─────────────────────────────────────────────
# STAGE 1: PRE-PROCESSING
# Decode obfuscated / encoded payloads before
# feature extraction so we're working on the
# actual intent, not the wrapper.
# ─────────────────────────────────────────────

def decode_base64_payload(script: str) -> str:
    """
    Detects and decodes -EncodedCommand or any long
    base64 blob inside the script string.
    Returns the decoded content appended to original.
    """
    # Match -EncodedCommand value
    enc_match = re.search(
        r'-[Ee]nco(?:dedCommand|ded|d)?\s+([A-Za-z0-9+/=]{20,})',
        script
    )
    if enc_match:
        b64 = enc_match.group(1)
        try:
            # PowerShell encodes in UTF-16-LE
            decoded = base64.b64decode(b64).decode('utf-16-le', errors='ignore')
            return script + " [DECODED]: " + decoded
        except Exception:
            pass

    # Match any standalone long base64 blob
    blobs = re.findall(r'[A-Za-z0-9+/]{60,}={0,2}', script)
    for blob in blobs:
        try:
            decoded = base64.b64decode(blob).decode('utf-8', errors='ignore')
            if len(decoded) > 10 and decoded.isprintable():
                return script + " [DECODED]: " + decoded
        except Exception:
            pass

    return script


def decode_hex_payload(script: str) -> str:
    """
    Detects hex-encoded strings (0x... or continuous hex blocks)
    and decodes them.
    """
    hex_blobs = re.findall(r'(?:0x)?([0-9a-fA-F]{20,})', script)
    for blob in hex_blobs:
        try:
            decoded = bytes.fromhex(blob).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 5:
                return script + " [HEX_DECODED]: " + decoded
        except Exception:
            pass
    return script


def preprocess(script: str) -> str:
    """Full preprocessing: decode → normalize → return enriched string."""
    script = decode_base64_payload(script)
    script = decode_hex_payload(script)
    return script


# ─────────────────────────────────────────────
# STAGE 2: FEATURE EXTRACTION
# 5 feature groups → combined into one vector
# ─────────────────────────────────────────────

# --- 2a. Entropy Features ---

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def entropy_features(script: str) -> dict:
    return {
        "entropy_full": shannon_entropy(script),
        "entropy_tokens": shannon_entropy(re.sub(r'\s+', '', script)),
        "length": len(script),
        "length_log": math.log1p(len(script)),
    }


# --- 2b. Structural / Flag Features ---

SUSPICIOUS_FLAGS = {
    "flag_bypass":           r'(?i)-executionpolicy\s+bypass',
    "flag_unrestricted":     r'(?i)-executionpolicy\s+unrestricted',
    "flag_noprofile":        r'(?i)-noprofile',
    "flag_noninteractive":   r'(?i)-noninteractive',
    "flag_hidden":           r'(?i)-windowstyle\s+hidden',
    "flag_encoded_cmd":      r'(?i)-encodedcommand|-encoded\b',
    "flag_noexit":           r'(?i)-noexit',
    "flag_nologoless":       r'(?i)-nologo',
    "flag_env_var":          r'%[A-Z_]+%',         # env vars like %COMSPEC%
    "flag_pipe_input":       r'\|\s*["\']?.*\.ps1',
    "flag_temp_path":        r'(?i)\\temp\\|appdata\\local\\temp',
    "flag_guid_filename":    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "flag_iex":              r'(?i)\biex\b|invoke-expression',
    "flag_download":         r'(?i)downloadstring|webclient|invoke-webrequest|\biwr\b',
    "flag_reflection":       r'(?i)\[reflection\.|assembly::load',
    "flag_set_content":      r'(?i)set-content|out-file',
    "flag_registry":         r'(?i)hklm:|hkcu:|registry::',
    "flag_wmi":              r'(?i)get-wmiobject|invoke-wmimethod|wmic',
    "flag_net_connection":   r'(?i)new-object\s+net\.webclient|tcpclient|udpclient',
    "flag_b64_blob":         r'[A-Za-z0-9+/]{60,}={0,2}',
    "flag_hex_blob":         r'(?:0x[0-9a-fA-F]{8,}|[0-9a-fA-F]{20,})',
    "flag_compress":         r'(?i)gzip|deflate|decompress|io\.compression',
    "flag_amsi_bypass":      r'(?i)amsi|system\.management\.automation',
    "flag_sc_create":        r'(?i)sc\.exe\s+create|new-service',
    "flag_cscript":          r'(?i)cscript|wscript',
    "flag_cmd_invoke":       r'(?i)cmd\.exe.*\/c|cmd\s+\/c',
}

def structural_features(script: str) -> dict:
    return {k: int(bool(re.search(v, script))) for k, v in SUSPICIOUS_FLAGS.items()}


# --- 2c. Token / N-gram Features ---

def tokenize(script: str) -> list:
    """Split on whitespace and punctuation, lowercase."""
    tokens = re.findall(r"[a-zA-Z_\-][a-zA-Z0-9_\-\.]*", script.lower())
    return tokens


# Vocabulary of known-suspicious tokens (weak signals individually, strong combined)
SUSPICIOUS_TOKENS = {
    "tok_powershell", "tok_cmd", "tok_bypass", "tok_encoded",
    "tok_hidden", "tok_invoke", "tok_expression", "tok_webclient",
    "tok_downloadstring", "tok_iex", "tok_reflection", "tok_assembly",
    "tok_gzip", "tok_base64", "tok_decompress", "tok_frombase64string",
    "tok_tobase64string", "tok_convert", "tok_marshal",
    "tok_virtualalloc", "tok_createthread", "tok_shellcode",
}

def token_features(script: str) -> dict:
    tokens = tokenize(script)
    total = len(tokens) if tokens else 1
    unique = len(set(tokens))
    token_set = {"tok_" + t for t in tokens}
    suspicious_hits = len(token_set & SUSPICIOUS_TOKENS)

    return {
        "token_count": total,
        "token_unique_ratio": unique / total,
        "token_suspicious_count": suspicious_hits,
        "token_suspicious_ratio": suspicious_hits / total,
        "token_avg_len": sum(len(t) for t in tokens) / total,
    }


# --- 2d. Obfuscation Indicators ---

def obfuscation_features(script: str) -> dict:
    # Ratio of non-alpha characters (high = likely obfuscated)
    non_alpha = sum(1 for c in script if not c.isalpha() and not c.isspace())
    total = max(len(script), 1)

    # Count backtick escapes (PowerShell obfuscation trick)
    backtick_count = script.count('`')

    # String concatenation count (e.g. "po"+"wer"+"shell")
    concat_count = len(re.findall(r'["\'][^"\']*["\'\s]*\+["\'\s]*["\']', script))

    # Char casting obfuscation ([char]0x50 etc.)
    char_cast_count = len(re.findall(r'\[char\]', script, re.I))

    # Dollar-sign variable count
    var_count = len(re.findall(r'\$[a-zA-Z_]', script))

    return {
        "obf_non_alpha_ratio": non_alpha / total,
        "obf_backtick_count": backtick_count,
        "obf_concat_count": concat_count,
        "obf_char_cast_count": char_cast_count,
        "obf_var_count": var_count,
        "obf_has_b64": int(bool(re.search(r'[A-Za-z0-9+/]{60,}={0,2}', script))),
        "obf_has_hex": int(bool(re.search(r'0x[0-9a-fA-F]{6,}', script))),
    }


# --- 2e. Path / Context Features ---

def path_features(script: str) -> dict:
    paths = re.findall(r'[A-Za-z]:\\[^\s"\']+', script)
    has_system32 = int(any('system32' in p.lower() for p in paths))
    has_temp = int(any('temp' in p.lower() or 'tmp' in p.lower() for p in paths))
    has_appdata = int(any('appdata' in p.lower() for p in paths))
    has_programdata = int(any('programdata' in p.lower() for p in paths))
    has_network_path = int(bool(re.search(r'\\\\[a-zA-Z0-9\-\.]+\\', script)))
    has_unc_drive = int(bool(re.search(r'[A-Za-z]:\\', script)))

    return {
        "path_count": len(paths),
        "path_has_system32": has_system32,
        "path_has_temp": has_temp,
        "path_has_appdata": has_appdata,
        "path_has_programdata": has_programdata,
        "path_has_network": has_network_path,
        "path_has_unc": has_unc_drive,
    }


# ─────────────────────────────────────────────
# STAGE 3: COMBINE INTO FEATURE VECTOR
# ─────────────────────────────────────────────

def extract_features(raw_script: str) -> dict:
    """Full pipeline: preprocess → extract all feature groups → return flat dict."""
    processed = preprocess(raw_script)
    features = {}
    features.update(entropy_features(processed))
    features.update(structural_features(processed))
    features.update(token_features(processed))
    features.update(obfuscation_features(processed))
    features.update(path_features(processed))
    return features


def build_feature_matrix(scripts: list) -> pd.DataFrame:
    rows = [extract_features(s) for s in scripts]
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────
# STAGE 4: ANOMALY SCORING
# Isolation Forest (fast, scales to 30M with
# batch processing) + optional Autoencoder
# ─────────────────────────────────────────────

def anomaly_score_isolation_forest(df: pd.DataFrame) -> np.ndarray:
    """
    Returns anomaly scores. More negative = more anomalous.
    Isolation Forest works well unsupervised at large scale.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X = scaler.fit_transform(df.values)

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.05,   # assume ~5% of data is anomalous (tune this)
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X)
    scores = clf.decision_function(X)   # lower = more anomalous
    labels = clf.predict(X)             # -1 = anomaly, 1 = normal
    return scores, labels, scaler, clf


# ─────────────────────────────────────────────
# STAGE 5: CLUSTERING (UMAP + HDBSCAN)
# Reduces dimensions for visualization and
# groups similar scripts together — helps
# identify attack families/campaigns
# ─────────────────────────────────────────────

def cluster_scripts(df: pd.DataFrame, scaler):
    """
    UMAP for dimensionality reduction → HDBSCAN for clustering.
    Returns 2D embeddings + cluster labels.
    Install: pip install umap-learn hdbscan
    """
    try:
        import umap
        import hdbscan
        from sklearn.preprocessing import StandardScaler

        X = scaler.transform(df.values)

        reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=15)
        embedding = reducer.fit_transform(X)

        clusterer = hdbscan.HDBSCAN(min_cluster_size=5, min_samples=2)
        cluster_labels = clusterer.fit_predict(embedding)

        return embedding, cluster_labels

    except ImportError:
        print("umap-learn or hdbscan not installed. Run: pip install umap-learn hdbscan")
        return None, None


# ─────────────────────────────────────────────
# STAGE 6: AUTOENCODER (PyTorch)
# Learns to reconstruct "normal" scripts.
# High reconstruction error = anomaly.
# Best used after Isolation Forest as a 2nd pass.
# ─────────────────────────────────────────────

def build_autoencoder(input_dim: int):
    """
    Lightweight autoencoder. Bottleneck forces learning
    of compressed representation of normal behavior.
    """
    try:
        import torch
        import torch.nn as nn

        class Autoencoder(nn.Module):
            def __init__(self, input_dim):
                super().__init__()
                self.encoder = nn.Sequential(
                    nn.Linear(input_dim, 64),
                    nn.ReLU(),
                    nn.Linear(64, 32),
                    nn.ReLU(),
                    nn.Linear(32, 16),   # bottleneck
                )
                self.decoder = nn.Sequential(
                    nn.Linear(16, 32),
                    nn.ReLU(),
                    nn.Linear(32, 64),
                    nn.ReLU(),
                    nn.Linear(64, input_dim),
                )

            def forward(self, x):
                return self.decoder(self.encoder(x))

            def reconstruction_error(self, x):
                with torch.no_grad():
                    recon = self.forward(x)
                    return torch.mean((recon - x) ** 2, dim=1)

        return Autoencoder(input_dim)

    except ImportError:
        print("PyTorch not installed. Run: pip install torch")
        return None


def train_autoencoder(model, X_train_tensor, epochs=50, lr=1e-3):
    """Train autoencoder on (assumed mostly benign) data."""
    try:
        import torch
        import torch.nn as nn

        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        loss_fn = nn.MSELoss()

        model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            recon = model(X_train_tensor)
            loss = loss_fn(recon, X_train_tensor)
            loss.backward()
            optimizer.step()
            if (epoch + 1) % 10 == 0:
                print(f"  Epoch {epoch+1}/{epochs} | Loss: {loss.item():.6f}")

        return model
    except ImportError:
        return None


# ─────────────────────────────────────────────
# STAGE 7: RISK SCORING
# Combine Isolation Forest score + autoencoder
# reconstruction error → final risk score 0-100
# ─────────────────────────────────────────────

def compute_risk_score(iso_score: float, recon_error: float = None,
                        iso_weight=0.6, ae_weight=0.4) -> float:
    """
    Normalizes and combines anomaly signals into a 0–100 risk score.
    If no autoencoder, uses iso_score alone.
    """
    # iso_score is negative for anomalies, normalize to 0-1 (1 = most anomalous)
    iso_norm = 1 / (1 + math.exp(iso_score * 5))   # sigmoid inversion

    if recon_error is not None:
        ae_norm = min(recon_error / 0.5, 1.0)       # cap at 0.5 error = 100%
        score = (iso_norm * iso_weight + ae_norm * ae_weight) * 100
    else:
        score = iso_norm * 100

    return round(score, 2)


# ─────────────────────────────────────────────
# MAIN: Run the full pipeline on sample data
# ─────────────────────────────────────────────

SAMPLE_SCRIPTS = [
    """C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command "& {$OutputEncoding = [Console]::OutputEncoding =[System.Text.Encoding]::UTF8;$scriptFileStream = [System.IO.File]::Open('C:\\ProgramData\\Microsoft\\Windows Defender\\DataCollection\\9f2a6e93.ps1')}" """,
    """powershell.exe  -command "O:\\SPaaS\\SPaaSScheduler\\Scripts\\IPCSelfService\\ProcessOrders.ps1" """,
    """powershell  -executionpolicy bypass -file "O:\\Finance GL\\Common\\Scripts\\XFB_RECEIVE_FLX21691.PS1" """,
    """PowerShell  -NoProfile -ExecutionPolicy Bypass -Command "& 'O:\\PROG\\General\\MRLS/Sql-AgentJob-Execution.ps1' -ServerName 'tm01-dbp-e-ptm-fcrm.ing.net'" """,
    """PowerShell  -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand UwBlAHQALQBTAHQAcgBpAGMAdABNAG8AZABlACAALQBWAGUAcgBzAGkAbwBuACAATABhAHQAZQBzAHQACgAkAHAAYQB0AGgAIAA9ACAAJwBjADoAXAB0AGUAbQBwAA==""",
    """C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command "& {if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {$OutputEncoding = [Console]::OutputEncoding}}" """,
    """powershell.exe  -command  $input |"D:\\Apps\\SplunkUniversalForwarder\\bin\\splunk-powershell.ps1"  "D:\\Apps\\SplunkUniversalForwarder"  40305a6d96b95b62""",
    """C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe  -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command ". 'P:\\Agent2\\_work\\_temp\\3d80a12e-5770-4892-bd12-475feb28b98b.ps1'" """,
    """C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe  -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command ". 'P:\\Agent2\\_work\\_temp\\3e671615-7456-44fd-9387-d8b21d13d6c4.ps1'" """,
    """C:\\WINDOWS\\system32\\cmd.exe /c powershell %IFSSCDIR%/IFSYS_WF_LOAD IUSWFACK DFFT0043202602092330ACK_100014373887""",
]


if __name__ == "__main__":
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    print("=" * 60)
    print("  PowerShell Anomaly Detection Pipeline")
    print("=" * 60)

    # 1. Build feature matrix
    print("\n[1] Extracting features...")
    df = build_feature_matrix(SAMPLE_SCRIPTS)
    print(f"    Feature matrix shape: {df.shape}")
    print(f"    Features: {list(df.columns)}\n")

    # 2. Anomaly scoring
    print("[2] Running Isolation Forest...")
    scores, labels, scaler, clf = anomaly_score_isolation_forest(df)

    # 3. Risk scores
    print("\n[3] Risk Scores per Script:")
    print(f"{'#':<4} {'Score':>7} {'Label':>8}  {'Preview'}")
    print("-" * 70)
    for i, (sc, lb) in enumerate(zip(scores, labels)):
        risk = compute_risk_score(sc)
        tag = "⚠ ANOMALY" if lb == -1 else "  normal "
        preview = SAMPLE_SCRIPTS[i][:55].replace('\n', ' ')
        print(f"{i+1:<4} {risk:>6.1f}%  {tag}  {preview}...")

    # 4. Feature importance snapshot
    print("\n[4] Top suspicious feature values for most anomalous sample:")
    most_anomalous_idx = np.argmin(scores)
    row = df.iloc[most_anomalous_idx]
    top_features = row.sort_values(ascending=False).head(10)
    for feat, val in top_features.items():
        print(f"    {feat:<40} {val:.4f}")

    print("\n[5] Feature matrix summary:")
    print(df.describe().round(3).to_string())
    print("\nPipeline ready. Scale to 30M by processing in batches of 50k.")
    print("Next steps: train autoencoder on full corpus, add UMAP+HDBSCAN clustering.")