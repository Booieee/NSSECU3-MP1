import os
import csv
import hashlib
import yara
import psutil
from collections import Counter


class ForensicScanner:
    def __init__(self, target_path, rules_path, expected_count=220):
        self.target_path = target_path
        self.rules = yara.compile(filepath=rules_path)
        self.expected_count = expected_count
        self.results = []
        self.type_counts = Counter()
        self.processed_count = 0

    def get_first_50_bytes(self, file_path):
        """Extracts first 50 bytes in hex format (Read-Only)."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(50)
                return data.hex().upper()
        except Exception:
            return "ERROR_READING"

    def compute_sha256(self, file_path):
        """Computes SHA256 hash (Read-Only)."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "ERROR_HASHING"

    def scan_file(self, file_path):
        """Processes an individual file and matches against YARA rules."""
        try:
            matches = self.rules.match(file_path)
            detected_type = matches[0].rule if matches else "Unknown/Data"

            file_stats = os.stat(file_path)

            file_data = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_stats.st_size,
                "sha256": self.compute_sha256(file_path),
                "first_50_bytes_hex": self.get_first_50_bytes(file_path),
                "detected_type": detected_type,
                "yara_matches": ", ".join([str(m) for m in matches])
            }

            self.type_counts[detected_type] += 1
            self.processed_count += 1
            return file_data
        except Exception as e:
            print(f"[!] Could not process {file_path}: {e}")
            return None

    def run_scan(self):
        """Recursively traverses the target path."""
        print(f"[*] Starting recursive scan of: {self.target_path}")
        for root, dirs, files in os.walk(self.target_path):
            for file in files:
                full_path = os.path.join(root, file)
                result = self.scan_file(full_path)
                if result:
                    self.results.append(result)

    def export_csv(self, output_file="forensic_report.csv"):
        keys = ["file_path", "file_name", "file_size", "sha256", "first_50_bytes_hex", "detected_type", "yara_matches"]
        with open(output_file, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(self.results)
        print(f"[+] Report exported to {output_file}")


def list_mounted_drives():
    print("\n--- Mounted Devices ---")
    partitions = psutil.disk_partitions()
    for p in partitions:
        print(f"Device: {p.device} | Mountpoint: {p.mountpoint} | FSType: {p.fstype} | Opts: {p.opts}")
    print("------------------------\n")


if __name__ == "__main__":
    list_mounted_drives()

    target = input("Enter the mountpoint to scan (e.g., E:\\): ").strip()

    if not os.path.exists(target):
        print("[!] Target path does not exist.")
    else:
        scanner = ForensicScanner(target, "signatures.yar")
        scanner.run_scan()
        scanner.export_csv()

        print("\n--- Scan Summary ---")
        print(f"Total Files Processed: {scanner.processed_count}")
        for ftype, count in scanner.type_counts.items():
            print(f" - {ftype}: {count}")

        if scanner.processed_count != 220:
            print(f"\n[WARNING] Expected 220 files, but found {scanner.processed_count}!")
        else:
            print("\n[SUCCESS] Exactly 220 files were identified and processed.")