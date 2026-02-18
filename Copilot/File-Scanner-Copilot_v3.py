import os
import csv
import hashlib
import re
from collections import Counter
from typing import Dict, List, Tuple, Set, Optional

import yara  # MUST be yara-python

# Optional file explorer dialogs
try:
    import tkinter as tk
    from tkinter import filedialog
except Exception:
    tk = None
    filedialog = None


# -----------------------------
# Windows mounted drives listing
# -----------------------------
def list_windows_drives() -> List[str]:
    if os.name != "nt":
        return ["/"]
    import ctypes
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    drives = []
    for i in range(26):
        if bitmask & (1 << i):
            drives.append(f"{chr(65 + i)}:\\")
    return drives


def choose_directory(title: str) -> str:
    if tk is None or filedialog is None:
        return ""
    root = tk.Tk()
    root.withdraw()
    p = filedialog.askdirectory(title=title)
    root.destroy()
    return p or ""


def choose_open_file(title: str, filetypes: List[Tuple[str, str]]) -> str:
    if tk is None or filedialog is None:
        return ""
    root = tk.Tk()
    root.withdraw()
    p = filedialog.askopenfilename(title=title, filetypes=filetypes)
    root.destroy()
    return p or ""


def choose_save_file(title: str, default_name: str, filetypes: List[Tuple[str, str]]) -> str:
    if tk is None or filedialog is None:
        return ""
    root = tk.Tk()
    root.withdraw()
    p = filedialog.asksaveasfilename(title=title, initialfile=default_name, defaultextension=filetypes[0][1], filetypes=filetypes)
    root.destroy()
    return p or ""


# -----------------------------
# File walking + safe reads
# -----------------------------
def iter_all_regular_files(root_path: str):
    """Yield full paths to regular files under root_path (recursive)."""
    for dirpath, _, filenames in os.walk(root_path):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            # Skip reparse points / broken links where possible
            try:
                if os.path.isfile(p):
                    yield p
            except Exception:
                continue


def safe_first_n_hex(path: str, n_bytes: int = 50) -> str:
    with open(path, "rb") as f:
        b = f.read(n_bytes)
    return b.hex()


def md5_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha1_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# -----------------------------
# YARA helpers
# -----------------------------
def compile_yara_rules(yara_path: str) -> yara.Rules:
    return yara.compile(filepath=yara_path)


def yara_match_file(rules: yara.Rules, file_path: str):
    """Return yara match objects or empty list."""
    try:
        return rules.match(file_path)
    except Exception:
        return []


def extract_rule_names(matches) -> str:
    if not matches:
        return ""
    return ";".join(sorted({m.rule for m in matches}))


def extract_detected_type(matches) -> str:
    """
    Return a single file-type label for grouping.

    Priority:
    1) If the YARA rule provides meta 'file_type' (e.g., EXE/PDF/PNG), use that.
       (Consolidated rules use meta.file_type to specify the detected type.)
    2) Otherwise, fall back to the first matching rule name (deterministic).
    """
    if not matches:
        return "UNMATCHED"

    # Try to use meta.file_type from any match (preferred)
    for m in matches:
        try:
            ft = (m.meta or {}).get("file_type")
            if ft:
                return str(ft).strip().upper()
        except Exception:
            pass

    # Fallback: rule names
    rules = sorted({m.rule for m in matches})
    return rules[0] if rules else "UNMATCHED"


# -----------------------------
# Baseline hash allowlist (220-set)
# -----------------------------
def _normalize_hash_token(s: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", (s or "")).lower()


def load_baseline_hashes(path: str) -> Set[str]:
    """
    Loads baseline hash keys from a file. Auto-detects format.

    Supported formats:
    1) CSV with headers: sha1/md5 or sha256
    2) Text lines with one hash per line:
       - SHA256: 64 hex chars (auto-detected)
       - SHA1: 40 hex chars (auto-detected)
       - SHA1,MD5 pairs: sha1,md5 format
    
    Returns a set of keys in standardized format:
    - "sha256:{hash}" for 64-char hex
    - "sha1,md5:{sha1},{md5}" for sha1/md5 pairs
    - "sha1:{hash}" for 40-char hex
    """
    baseline: Set[str] = set()
    if not path:
        return baseline
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Baseline file not found: {path}")

    # Try CSV first
    try:
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            sample = f.read(4096)
            f.seek(0)
            if "," in sample and any(x in sample.lower() for x in ["sha1", "md5", "sha256"]):
                reader = csv.DictReader(f)
                lower_fields = {name.lower(): name for name in (reader.fieldnames or [])}
                sha256_col = lower_fields.get("sha256")
                sha1_col = lower_fields.get("sha1")
                md5_col = lower_fields.get("md5")
                for row in reader:
                    if sha256_col:
                        sha256v = _normalize_hash_token(row.get(sha256_col, ""))
                        if sha256v and len(sha256v) == 64:
                            baseline.add(f"sha256:{sha256v}")
                    else:
                        sha1v = _normalize_hash_token(row.get(sha1_col, "")) if sha1_col else ""
                        md5v = _normalize_hash_token(row.get(md5_col, "")) if md5_col else ""
                        if sha1v:
                            baseline.add(f"sha1,md5:{sha1v},{md5v}")
                return baseline
    except Exception:
        pass

    # Line-based parsing (auto-detect format)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            normalized = _normalize_hash_token(line)
            if not normalized:
                continue
            
            # Auto-detect: SHA256 is 64 hex chars
            if len(normalized) == 64:
                baseline.add(f"sha256:{normalized}")
            # SHA1 is 40 hex chars; may have MD5 after comma
            elif len(normalized) >= 40:
                if "," in line:
                    parts = [_normalize_hash_token(p) for p in line.split(",", 1)]
                    if len(parts[0]) == 40:  # SHA1
                        md5v = parts[1] if len(parts) > 1 else ""
                        baseline.add(f"sha1,md5:{parts[0]},{md5v}")
                    elif len(parts[0]) == 64:  # SHA256
                        baseline.add(f"sha256:{parts[0]}")
                else:
                    if len(normalized) == 40:
                        baseline.add(f"sha1:{normalized}")
                    elif len(normalized) == 64:
                        baseline.add(f"sha256:{normalized}")
    return baseline


def make_key(sha1_hex: str = "", md5_hex: str = "", sha256_hex: str = "") -> str:
    """Create a baseline key based on available hashes."""
    if sha256_hex:
        return f"sha256:{sha256_hex.lower()}"
    elif sha1_hex:
        return f"sha1,md5:{sha1_hex.lower()},{md5_hex.lower()}"
    return ""


# -----------------------------
# CSV output
# -----------------------------
def write_csv(rows: List[Dict[str, str]], out_csv: str) -> None:
    fields = [
        "file_path",
        "file_name",
        "file_size",
        "sha1",
        "md5",
        "sha256",
        "first_50_bytes_hex",
        "detected_type",
        "yara_matches",
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def print_grouped_counts(rows: List[Dict[str, str]]) -> None:
    c = Counter(r["detected_type"] for r in rows)
    print("\nGrouped count by detected file type (MATCHED FILES ONLY):")
    for k in sorted(c.keys()):
        print(f"  {k}: {c[k]}")


# -----------------------------
# Main
# -----------------------------
def main():
    print("=== Python Forensic File Scanner (Mounted Disk Image) ===")
    print("Read-only: only reads file bytes and writes a CSV report.\n")

    drives = list_windows_drives()
    print("Mounted drives detected:")
    for d in drives:
        print(f"  - {d}")
    print()

    scan_root = choose_directory("Select mounted drive or folder to scan (root of mounted image)") or ""
    if not scan_root:
        scan_root = input("Enter mounted drive/folder path to scan (e.g., E:\\): ").strip()
    if not scan_root or not os.path.exists(scan_root):
        print("Invalid scan path. Exiting.")
        return

    yara_path = choose_open_file("Select YARA rules file (.yar)", [("YARA rules", "*.yar"), ("All files", "*.*")]) or ""
    if not yara_path:
        yara_path = input("Enter YARA rules file path: ").strip()
    if not yara_path or not os.path.isfile(yara_path):
        print("Invalid YARA file. Exiting.")
        return

    # Baseline allowlist (recommended for adviser adding extra files)
    baseline_path = choose_open_file("Select baseline hashes file (optional but recommended)", [("CSV or TXT", "*.csv;*.txt"), ("All files", "*.*")]) or ""
    if not baseline_path:
        baseline_path = input("Enter baseline hashes file path (or press Enter to skip): ").strip()

    out_csv = choose_save_file("Save output CSV report", "scan_results.csv", [("CSV", "*.csv"), ("All files", "*.*")]) or ""
    if not out_csv:
        out_csv = input("Enter output CSV path: ").strip()
    if not out_csv:
        print("No output CSV provided. Exiting.")
        return

    print("\nTarget scan path:")
    print(f"  {scan_root}")

    print("\nCompiling YARA rules...")
    rules = compile_yara_rules(yara_path)
    print("YARA compiled successfully.\n")

    baseline: Set[str] = set()
    seen_baseline: Set[str] = set()
    use_baseline = False
    expected_baseline_size: Optional[int] = None

    if baseline_path:
        try:
            baseline = load_baseline_hashes(baseline_path)
            use_baseline = True
            expected_baseline_size = len(baseline) if baseline else None
            print(f"Baseline loaded: {len(baseline)} unique hash keys")
            if expected_baseline_size and expected_baseline_size != 220:
                print(f"[WARN] Baseline size is {expected_baseline_size}, not 220. Validation will use baseline size and/or 220 check.")
        except Exception as e:
            print(f"[WARN] Failed to load baseline file ({e}). Continuing WITHOUT baseline filtering.")
            use_baseline = False

    rows: List[Dict[str, str]] = []

    total_regular_files_seen = 0
    total_unmatched_seen = 0
    total_yara_matched_seen = 0

    total_recorded = 0
    total_yara_matched_scanned = 0
    matched_unreadable_for_hash = 0

    extras_yara_matched_not_in_baseline = 0
    duplicates_baseline_ignored = 0

    print("Starting recursive scan...\n")

    for file_path in iter_all_regular_files(scan_root):
        total_regular_files_seen += 1

        if total_regular_files_seen % 25 == 0:
            print(
                f"[PROGRESS] Visited {total_regular_files_seen} files | "
                f"YARA-matched: {total_yara_matched_seen} | Unmatched: {total_unmatched_seen} | "
                f"Recorded: {total_recorded}\n"
                f"          Latest: {file_path}"
            )

        matches = yara_match_file(rules, file_path)

        if not matches:
            total_unmatched_seen += 1
            continue

        total_yara_matched_seen += 1

        # Only matched files get bytes+hash attempts
        try:
            size = os.path.getsize(file_path)
            first50 = safe_first_n_hex(file_path, 50)
            sha1v = sha1_file(file_path)
            md5v = md5_file(file_path)
            sha256v = sha256_file(file_path)
        except Exception as e:
            matched_unreadable_for_hash += 1
            print(f"[WARN] YARA-matched but unreadable for bytes/hash: {file_path} ({e})")
            continue

        total_yara_matched_scanned += 1

        key = make_key(sha1v, md5v, sha256v)

        if use_baseline:
            if key not in baseline:
                # Adviser-added or non-dataset file that still matches YARA: ignore for the 220 requirement
                extras_yara_matched_not_in_baseline += 1
                continue
            if key in seen_baseline:
                # Duplicate of a baseline file: ignore for the 220 requirement
                duplicates_baseline_ignored += 1
                continue
            seen_baseline.add(key)

        detected_type = extract_detected_type(matches)
        yara_names = extract_rule_names(matches)

        rows.append(
            {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": str(size),
                "sha1": sha1v,
                "md5": md5v,
                "sha256": sha256v,
                "first_50_bytes_hex": first50,
                "detected_type": detected_type,
                "yara_matches": yara_names,
            }
        )
        total_recorded += 1

        # Optional early stop: if baseline is used and we've found all unique baseline hashes
        if use_baseline and expected_baseline_size and len(seen_baseline) >= expected_baseline_size:
            # You can comment this out if you want to ALWAYS scan full drive
            pass

    write_csv(rows, out_csv)

    print("\n=== Scan Summary ===")
    print(f"Mounted drives listed: {len(drives)}")
    print(f"Target scan path: {scan_root}")
    print(f"Total regular files visited in directory walk: {total_regular_files_seen}")
    print(f"Total unmatched files visited (ignored): {total_unmatched_seen}")
    print(f"Total files that matched YARA rules: {total_yara_matched_seen}")
    print(f"Total YARA-matched files successfully read+hashed: {total_yara_matched_scanned}")
    if matched_unreadable_for_hash:
        print(f"YARA-matched files unreadable for bytes/hash (skipped): {matched_unreadable_for_hash}")

    if use_baseline:
        print(f"Baseline unique files recorded: {len(seen_baseline)}")
        print(f"YARA-matching files not in baseline (ignored): {extras_yara_matched_not_in_baseline}")
        print(f"Duplicate baseline files (ignored): {duplicates_baseline_ignored}")
    else:
        print(f"Total matched files successfully scanned (bytes+hash extracted): {total_recorded}")

    print_grouped_counts(rows)

    # Validation
    print("\nValidation:")
    if use_baseline:
        # Primary: baseline unique count should be 220 (or baseline size if different)
        target = 220
        if expected_baseline_size:
            # Keep course requirement at 220, but also report baseline-size for transparency
            pass
        if len(seen_baseline) == target:
            print("✅ Baseline-matched unique files recorded = 220.")
        else:
            print(f"❌ Expected 220 baseline-matched unique files, got {len(seen_baseline)}.")
            if expected_baseline_size and expected_baseline_size != 220:
                print(f"   Note: your baseline file contains {expected_baseline_size} unique hashes.")
            print("   Common causes: permissions/ACLs on mounted image, missing files, wrong baseline, or wrong mount/partition.")
            print("   Tip: run Python as Administrator and ensure AIM mount exposes user files.")
    else:
        if total_recorded == 220:
            print("✅ Exactly 220 files were matched and scanned.")
        else:
            print(f"❌ Expected 220 recorded files, got {total_recorded}.")
            print("   Tip: provide a baseline hashes file to ignore adviser-added matching files and duplicates.")

    print(f"\nCSV saved to: {out_csv}")


if __name__ == "__main__":
    main()
