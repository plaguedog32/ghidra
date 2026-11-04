"""Extract retained Java bitfield composite expectations into Rust test data.

Usage: python -I extract_fixtures.py <repo root> <output .rs>
Only string literals passed to CompositeTestUtils.assertExpectedComposite are
read; commented-out tests are skipped. No Java is compiled or executed.
"""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
base = root / 'Ghidra/Features/Base/src/test/java/ghidra/program/model/data'
files = [
    ('GCC_LE_STRUCTURES', 'StructureLittleEndianBitFieldTest.java'),
    ('GCC_BE_STRUCTURES', 'StructureBigEndianBitFieldTest.java'),
    ('MS_LE_STRUCTURES', 'MSVCStructureBitFieldTest.java'),
    ('GCC_LE_UNIONS', 'UnionLittleEndianBitFieldTest.java'),
    ('GCC_BE_UNIONS', 'UnionBigEndianBitFieldTest.java'),
    ('MS_LE_UNIONS', 'MSVCUnionBitFieldTest.java'),
]

literal = re.compile(r'"((?:[^"\\]|\\.)*)"')


def decode(text):
    return text.encode('utf-8').decode('unicode_escape')


def extract(path):
    lines = path.read_text(encoding='utf-8').splitlines()
    fixtures = []
    name = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('//'):
            i += 1
            continue
        found = re.search(r'get(?:Structure|Union)\("([^"]+)"\)', line)
        if found:
            name = found.group(1)
        if 'assertExpectedComposite(this,' in line:
            start = i + 1
            text = ''
            while True:
                # Strip trailing line comments that follow a closing literal.
                code = re.sub(r'\+\s*//.*$', '+', lines[i])
                for piece in literal.findall(code):
                    text += decode(piece)
                if re.search(r'\)\s*;', code) and ', struct' in code:
                    break
                i += 1
            fixtures.append((name, start, i + 1, text))
        i += 1
    return fixtures


def rust_string(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


parts = [
    '// Mechanically extracted by extract_fixtures.py from the retained Java tests in',
    '// Ghidra/Features/Base/src/test/java/ghidra/program/model/data/. Each entry is',
    '// (composite name, first line, last line, expected composite text). Do not',
    '// edit by hand; regenerate from the Java sources instead.',
    '',
]
total = 0
for constant, filename in files:
    fixtures = extract(base / filename)
    total += len(fixtures)
    parts.append(f'/// {filename}')
    parts.append(f'pub const {constant}: &[(&str, u32, u32, &str)] = &[')
    for name, start, end, text in fixtures:
        # rustfmt's layout, so regeneration is byte-identical after cargo fmt.
        parts.append('    (')
        parts.append(f'        "{name}",')
        parts.append(f'        {start},')
        parts.append(f'        {end},')
        parts.append(f'        {rust_string(text)},')
        parts.append('    ),')
    parts.append('];')
    parts.append('')
out.write_text('\n'.join(parts), encoding='utf-8')
print(total, 'fixtures written to', out)
