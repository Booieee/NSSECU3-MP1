import os
import csv
import hashlib
from collections import Counter
from typing import Dict, List, Tuple, Optional

import yara  # MUST be yara-python

import warnings
# Suppress noisy libyara RuntimeWarnings like "too many matches" without changing program outputs
warnings.filterwarnings("ignore", category=RuntimeWarning, module="yara")

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
    """List mounted drive letters on Windows without external dependencies."""
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
    p = filedialog.asksaveasfilename(
        title=title,
        defaultextension=os.path.splitext(default_name)[1] if "." in default_name else "",
        initialfile=default_name,
        filetypes=filetypes,
    )
    root.destroy()
    return p or ""


# -----------------------------
# File helpers (read-only)
# -----------------------------
def safe_first_n_hex(path: str, n: int = 50) -> str:
    """Read first n bytes and return uppercase hex. Pad with 00 if shorter."""
    with open(path, "rb") as f:
        b = f.read(n)
    if len(b) < n:
        b += b"\x00" * (n - len(b))
    return b.hex().upper()


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def iter_all_regular_files(root_dir: str):
    """Recursively yield all regular files."""
    for r, _, files in os.walk(root_dir):
        for name in files:
            p = os.path.join(r, name)
            if os.path.isfile(p):
                yield p


# -----------------------------
# YARA scanning logic
# -----------------------------
def compile_yara_rules(yara_path: str) -> yara.Rules:
    return yara.compile(filepath=yara_path)


def yara_match_file(rules: yara.Rules, file_path: str) -> Tuple[List[yara.Match], bool]:
    """
    Returns (matches, scan_ok).
    scan_ok=False means YARA could not read/scan the file (timeout/error).
    """
    try:
        return rules.match(filepath=file_path, timeout=60), True
    except yara.TimeoutError:
        print(f"[WARN] YARA timeout: {file_path}")
        return [], False
    except Exception as e:
        print(f"[WARN] Could not YARA-scan file: {file_path} ({e})")
        return [], False


def _type_from_rule_name(rule_name: str) -> Optional[str]:
    """
    Infer file type from rule name when meta is absent.
    We prefer specific OOXML types over generic ZIP/OOXML.
    """
    n = (rule_name or "").upper()

    # OOXML (prefer specific)
    if "DOCX" in n:
        return "DOCX"
    if "XLSX" in n:
        return "XLSX"
    if "PPTX" in n:
        return "PPTX"
    if "OOXML" in n:
        return "OOXML"

    # Other common types
    if "PDF" in n:
        return "PDF"
    if "PNG" in n:
        return "PNG"
    if "JPEG" in n or "JPG" in n:
        return "JPEG"
    if "MP3" in n:
        return "MP3"
    if "WAV" in n:
        return "WAV"
    if "GIF" in n:
        return "GIF"
    if "RAR" in n:
        return "RAR"
    if "GZ" in n or "GZIP" in n:
        return "GZIP"
    if "ISO" in n:
        return "ISO"
    if "ZIP" in n:
        return "ZIP"
    if "EXE" in n or "PE" in n:
        return "EXE"
    if "DLL" in n:
        return "DLL"
    if "PS1" in n or "POWERSHELL" in n:
        return "PS1"
    if "BAT" in n or "CMD" in n:
        return "BAT"
    if "TXT" in n or "TEXT" in n:
        return "TXT"
    if "UTF16" in n or "UTF-16" in n:
        return "TXT_UTF16"
    if "HTML" in n:
        return "HTML"
    if "XML" in n:
        return "XML"
    if "JSON" in n:
        return "JSON"

    return None


def extract_detected_type(matches: List[yara.Match]) -> str:
    """
    Determine detected type for a file.
    Priority:
      1) rule meta keys: filetype / file_type (if present)
      2) rule name heuristic (since your YAR intentionally avoids meta)
      3) rule tags (if any)
      4) UNKNOWN
    If multiple rules match, returns unique types joined with '|'.
    """
    types: List[str] = []

    # 1) meta if present
    for m in matches:
        meta = getattr(m, "meta", {}) or {}
        ft = meta.get("filetype") or meta.get("file_type") or meta.get("FILETYPE") or meta.get("FILE_TYPE")
        if isinstance(ft, str) and ft.strip():
            types.append(ft.strip())

    # 2) rule-name heuristic
    if not types:
        for m in matches:
            rn = getattr(m, "rule", "") or ""
            t = _type_from_rule_name(rn)
            if t:
                types.append(t)

    # 3) tags fallback
    if not types:
        for m in matches:
            for tag in getattr(m, "tags", []) or []:
                t = _type_from_rule_name(tag)
                if t:
                    types.append(t)

    if not types:
        return "UNKNOWN"

    # stable unique preserving order
    seen = set()
    out = []
    for t in types:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return "|".join(out)


def extract_rule_names(matches: List[yara.Match]) -> str:
    return ";".join(getattr(m, "rule", str(m)) for m in matches)


# -----------------------------
# Output
# -----------------------------
def write_csv(rows: List[Dict[str, str]], out_csv: str) -> None:
    fields = [
        "file_path",
        "file_name",
        "file_size",
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
    print("\nGrouped count by detected file type (UNIQUE MATCHED FILES ONLY):")
    for k in sorted(c.keys()):
        print(f"  {k}: {c[k]}")




def print_file_type_distribution(rows: List[Dict[str, str]], expected_total: int = 220) -> None:
    """Print a simplified distribution like the reference screenshot."""
    c = Counter(r["detected_type"] for r in rows)
    undetected = max(0, expected_total - sum(c.values()))
    print("\nFile type distribution:")
    # Order to match your screenshot style
    order = [
        "Windows DLL or EXE",
        "MS Excel XLSX",
        "TXT File",
        "MS Word DOCX File",
        "Windows Batch",
        "PNG Image",
        "JPEG Image",
        "Powershell Script",
        "MS PowerPoint PPTX",
        "PDF Document",
    ]
    # Print ordered types first
    for k in order:
        if k in c:
            print(f"  {k:<28} : {c[k]}")
    # Print any other detected types not in the list
    for k in sorted(c.keys()):
        if k not in order and k != "UNKNOWN":
            print(f"  {k:<28} : {c[k]}")
    if undetected:
        print(f"\n  {'UNDETECTED':<28} : {undetected}")


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

    rows: List[Dict[str, str]] = []
    seen_sha256 = set()  # dedupe duplicates/copies/hardlinks

    # Counters requested for console output
    total_regular_files_seen = 0
    total_unmatched_seen = 0
    total_files_successfully_scanned = 0   # YARA scan succeeded (readable by YARA)
    total_matched_paths_seen = 0           # matched file paths (includes duplicates)
    total_unique_matched_scanned = 0       # unique by SHA256
    duplicate_matches_skipped = 0
    matched_unreadable_for_hash = 0
    yara_scan_failed = 0

    print("Starting recursive scan...\n")

    for file_path in iter_all_regular_files(scan_root):
        total_regular_files_seen += 1

        # Progress for ALL files (matched + unmatched)
        if total_regular_files_seen % 10 == 0:
            print(
                f"[PROGRESS] Visited {total_regular_files_seen} files | "
                f"Matched paths: {total_matched_paths_seen} | "
                f"Unmatched: {total_unmatched_seen} | "
                f"Unique matched&scanned: {total_unique_matched_scanned}\n"
                f"          Latest: {file_path}"
            )

        matches, ok = yara_match_file(rules, file_path)
        if ok:
            total_files_successfully_scanned += 1
        else:
            yara_scan_failed += 1

        if not matches:
            total_unmatched_seen += 1
            continue

        total_matched_paths_seen += 1

        # Only matched files get hashed/recorded
        try:
            size = os.path.getsize(file_path)
            first50 = safe_first_n_hex(file_path, 50)
            sha = sha256_file(file_path)
        except Exception as e:
            matched_unreadable_for_hash += 1
            print(f"[WARN] Matched but unreadable for bytes/hash: {file_path} ({e})")
            continue

        # Dedupe (unique targets)
        if sha in seen_sha256:
            duplicate_matches_skipped += 1
            continue

        seen_sha256.add(sha)
        total_unique_matched_scanned += 1

        detected_type = extract_detected_type(matches)
        yara_names = extract_rule_names(matches)

        rows.append(
            {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": str(size),
                "sha256": sha,
                "first_50_bytes_hex": first50,
                "detected_type": detected_type,
                "yara_matches": yara_names,
            }
        )

    write_csv(rows, out_csv)

    print("\n=== Scan Summary ===")
    print(f"List of mounted drives: {len(drives)}")
    print(f"Target scan path: {scan_root}\n")
    print(f"Total regular files visited in directory walk: {total_regular_files_seen}")
    print(f"Total unmatched files visited (ignored): {total_unmatched_seen}")

    # User-requested summary lines (names match your prompt)
    print(f"Total files successfully scanned: {total_files_successfully_scanned}")
    print(f"Total files found that match files the yara rules including duplicates: {total_matched_paths_seen}")
    print(f"Total unique files found that match files the yara rules: {total_unique_matched_scanned}")

    if duplicate_matches_skipped:
        print(f"Duplicate matched files skipped (same SHA256): {duplicate_matches_skipped}")
    if matched_unreadable_for_hash:
        print(f"Matched files unreadable for bytes/hash (skipped): {matched_unreadable_for_hash}")
    if yara_scan_failed:
        print(f"Files that YARA could not scan (skipped/failed): {yara_scan_failed}")

    print_grouped_counts(rows)
    print(f"\nCSV saved to: {out_csv}")


if __name__ == "__main__":
    main()
