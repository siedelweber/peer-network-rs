"""Checked source census for the supported Rust test/proptest and Python carriers.

Rust strings and comments are masked before balancing scopes; unsupported test
attributes or unaccounted runnable cases fail the later inventory equality.
"""

import ast
from collections import Counter
import json
from pathlib import Path
import re
import tomllib

from devperf import StructuralError

OWNERS = {'interchange': 'INTERCHANGE', 'cli-common': 'CLICOMMON',
          'execwrap': 'EXECWRAP', 'documents': 'DOCUMENTS', 'testkit': 'TESTKIT', 'graph': 'GRAPH', 'wallet': 'WALLET', 'host': 'HOST', 'records': 'RECORDS', 'verification': 'VERIFICATION'}
RAW_STRING = re.compile(r'(?:br|r)(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
DOC_ATTRIBUTE = re.compile(r'#\[doc\s*=\s*("(?:[^"\\]|\\.)*")\s*\]')


def rust_mask(text, comments=None):
    result = list(text)
    i = 0
    while i < len(text):
        start = i
        if text.startswith('//', i):
            i = text.find('\n', i)
            if i < 0: i = len(text)
            if comments is not None: comments.append(text[start:i])
        elif text.startswith('/*', i):
            depth = 1
            i += 2
            while i < len(text) and depth:
                if text.startswith('/*', i): depth += 1; i += 2
                elif text.startswith('*/', i): depth -= 1; i += 2
                else: i += 1
            if depth: raise StructuralError('unterminated Rust comment')
            if comments is not None: comments.append(text[start:i])
        else:
            raw = RAW_STRING.match(text, i)
            if raw:
                end = text.find('"'+raw[1], raw.end())
                if end < 0: raise StructuralError('unterminated Rust raw string')
                i = end+1+len(raw[1])
            elif text[i] == '"':
                i += 1
                while i < len(text):
                    if text[i] == '\\': i += 2
                    elif text[i] == '"': i += 1; break
                    else: i += 1
            elif text[i] == "'" and (char := CHAR_LITERAL.match(text, i)):
                i = char.end()
            else:
                i += 1
                continue
        for index in range(start, min(i, len(text))):
            if result[index] != '\n': result[index] = ' '
    return ''.join(result)


def rust_sites(path, text, package, owner, aliases=None):
    masked = rust_mask(text)
    braces = []
    ranges = []
    for match in re.finditer(r'[{}]', masked):
        if match[0] == '{': braces.append(match.start())
        elif not braces: raise StructuralError(f'{path}: unmatched closing brace')
        else: ranges.append((braces.pop(), match.start()))
    if braces: raise StructuralError(f'{path}: unmatched opening brace')
    modules = []
    properties = []
    ends = dict(ranges)
    for match in re.finditer(r'\bmod\s+(\w+)\s*\{|\bproptest\s*!\s*\{', masked):
        opening = match.end()-1
        if match[1]: modules.append((opening, ends[opening], match[1]))
        else: properties.append((opening, ends[opening]))
    relative = Path(path).parts[2:]
    if relative[0] == 'tests':
        binary = package+'::'+Path(relative[1]).stem
        prefix = [] if len(relative) == 2 else list(relative[2:-1])+([Path(relative[-1]).stem] if relative[-1] != 'mod.rs' else [])
    else:
        binary = package
        prefix = list(relative[1:-1])+([Path(relative[-1]).stem] if relative[-1] not in {'mod.rs','lib.rs','main.rs'} else [])
        if str(path) in (aliases or {}): prefix = aliases[str(path)]
    sites = []
    for mark in re.finditer(r'#\[\s*test\s*\]', masked):
        function = re.match(r'\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*\(', masked[mark.end():])
        if not function: raise StructuralError(f'{path}: unsupported test item')
        name = function[1]
        nesting = [m[2] for m in sorted(modules) if m[0] < mark.start() < m[1]]
        operation = binary+'::'+'::'.join(prefix+nesting+[name])
        before = text[:mark.start()].splitlines()
        doc = []
        for line in reversed(before):
            stripped = line.strip()
            attribute = DOC_ATTRIBUTE.fullmatch(stripped)
            if attribute:
                doc.append(json.loads(attribute[1]))
                continue
            if not stripped or stripped.startswith('#['): continue
            if stripped.startswith('///'): doc.append(stripped[3:].strip())
            else: break
        sites.append(dict(operation=operation, owner=owner, path=str(path),
                          line=text.count('\n', 0, mark.start())+1, function=name,
                          doc='\n'.join(reversed(doc)), language='rust',
                          property=any(a < mark.start() < b for a,b in properties)))
    return sites


def census(root):
    root = Path(root)
    sites = []
    for directory, owner in OWNERS.items():
        manifest = tomllib.loads((root/'packages'/directory/'Cargo.toml').read_text())
        package = manifest['package']['name']
        aliases = {}
        for parent in (root/'packages'/directory/'src').rglob('*.rs'):
            source = parent.read_text()
            for match in re.finditer(r'#\[path\s*=\s*"([^"]+)"\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;', source):
                target = parent.parent/match[1]
                aliases[str(target.relative_to(root))] = list(parent.parent.relative_to(root/'packages'/directory/'src').parts)+[match[2]]
        for path in sorted((root/'packages'/directory).rglob('*.rs')):
            if not {'src','tests'}.intersection(path.relative_to(root).parts[2:]): continue
            sites.extend(rust_sites(path.relative_to(root), path.read_text(), package, owner, aliases))
    for path in sorted((root/'ci').glob('test_*.py')):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef): continue
            for function in node.body:
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name.startswith('test_'):
                    sites.append(dict(operation=f'ci::{path.stem}.{node.name}.{function.name}',
                                      owner='ROOT', path=str(path.relative_to(root)), line=function.lineno,
                                      function=function.name, doc=ast.get_docstring(function) or '',
                                      language='python', property=False))
    if len({s['operation'] for s in sites}) != len(sites):
        raise StructuralError('duplicate source test identity')
    return sites


def property_roster(sites, declarations):
    actual = {s['operation'] for s in sites if s['property']}
    if actual != set(declarations):
        raise StructuralError(f'property declarations differ from proptest source: missing={sorted(actual-set(declarations))} stale={sorted(set(declarations)-actual)}')


def claim_mints(root):
    """Inventory comment/docstring mints independently of executable-site attachment."""
    root=Path(root)
    mints=Counter()
    def collect(owner, carriers):
        for carrier in carriers:
            for label in re.findall(r'(?<!\()´(claim:[a-z0-9-]+:[a-z0-9.-]+)´',carrier):
                mints[owner+'::'+label]+=1
    for directory,owner in OWNERS.items():
        for path in (root/'packages'/directory).rglob('*.rs'):
            if not {'src','tests'}.intersection(path.relative_to(root).parts[2:]): continue
            comments=[]
            source=path.read_text()
            masked=rust_mask(source,comments)
            for attribute in DOC_ATTRIBUTE.finditer(source):
                if masked[attribute.start():].startswith('#[doc'):
                    comments.append(json.loads(attribute[1]))
            collect(owner,comments)
    return mints
