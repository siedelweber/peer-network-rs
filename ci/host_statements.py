"""Guard the raw-client type boundary; SQL admission is enforced by Rust types."""
from pathlib import Path
import re
from source_sites import rust_mask


def production(text):
    masked=rust_mask(text)
    # Remove complete cfg(test) items, including external test-module declarations.
    pattern=re.compile(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]')
    for match in reversed(list(pattern.finditer(masked))):
        start=match.start();cursor=match.end();depth=0
        while cursor<len(masked):
            char=masked[cursor]
            if char=='{':depth+=1
            elif char=='}':
                depth-=1
                if depth==0:cursor+=1;break
            elif char==';' and depth==0:cursor+=1;break
            cursor+=1
        masked=masked[:start]+' '*(cursor-start)+masked[cursor:]
    return masked


def check(root=Path('.')):
    pending=[root/'packages/host/src/lib.rs'];seen=set()
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path)
        relative=path.relative_to(root).as_posix()
        text=production(path.read_text())
        if re.search(r'#\s*\[\s*path\s*=',text):
            raise ValueError('production module path needs reviewed traversal')
        directory=path.parent if path.name in ('lib.rs','mod.rs') else path.with_suffix('')
        for name in re.findall(r'\bmod\s+(\w+)\s*;',text):
            candidates=[directory/(name+'.rs'),directory/name/'mod.rs']
            found=[p for p in candidates if p.exists()]
            if len(found)!=1:raise ValueError('ambiguous production module')
            pending.extend(found)
        if path.name=='storage.rs':
            # Exactly the private field and constructor parameter, never a re-export.
            text,count=re.subn(r'(struct StatementClient\s*\{\s*raw|fn new\(raw):\s*tokio_postgres::Client',r'\1: CLOSED_DRIVER',text)
            if count!=2:raise ValueError('raw driver wrapper shape changed')
        if re.search(r'\bClient\b',text) or re.search(r'tokio_postgres\s*::\s*\*',text):
            raise ValueError('raw driver client outside the closed statement wrapper: '+relative)
    return True
