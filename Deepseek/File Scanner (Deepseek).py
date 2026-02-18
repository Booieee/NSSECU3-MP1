import re
from pathlib import Path

IN_PATH = Path(r"C:\Users\Wendel Leander\Downloads\rules_220_updated_fixed.yar")
OUT_PATH = Path(r"C:\Users\Wendel Leander\Downloads\rules_220_ready.yar")

text = IN_PATH.read_text(encoding="utf-8", errors="replace")

# 1) Avoid collision with YARA built-in `filesize`
text = re.sub(r'(?m)^(\s*)filesize\s*=\s*"', r'\1file_size = "', text)

# 2) For each rule block, copy meta sha256 into the condition comparison
rule_block_re = re.compile(r"(?s)(rule\s+\w+\s*\{.*?\n\})")

def fix_block(block: str) -> str:
    # Find meta sha256 = "...."
    m = re.search(r'(?m)^\s*sha256\s*=\s*"([0-9a-fA-F]{64})"\s*$', block)
    if not m:
        return block
    h = m.group(1).upper()

    # Replace `== sha256` with `== "<hash>"`
    block = re.sub(
        r'(?m)^\s*hash\.sha256\(\s*0\s*,\s*filesize\s*\)\s*==\s*sha256\s*$',
        f'    hash.sha256(0, filesize) == "{h}"',
        block
    )

    # Also handle cases with extra spaces or inline AND
    block = re.sub(
        r'hash\.sha256\(\s*0\s*,\s*filesize\s*\)\s*==\s*sha256\b',
        f'hash.sha256(0, filesize) == "{h}"',
        block
    )

    return block

blocks = rule_block_re.findall(text)
if not blocks:
    raise SystemExit("No YARA rule blocks found. Is this the correct file?")

fixed = []
last_end = 0
out = []
for m in rule_block_re.finditer(text):
    out.append(text[last_end:m.start()])
    out.append(fix_block(m.group(1)))
    last_end = m.end()
out.append(text[last_end:])
text2 = "".join(out)

# 3) Ensure hash module import exists at top
if 'import "hash"' not in text2:
    text2 = 'import "hash"\n\n' + text2

OUT_PATH.write_text(text2, encoding="utf-8", newline="\n")
print("Wrote:", OUT_PATH)
