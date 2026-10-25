"""Guard the raw-client type boundary; SQL admission is enforced by Rust types."""
from pathlib import Path
import re
from source_sites import rust_mask
from dependency_identity import metadata, spellings


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
    driver_names = spellings(metadata(root), 'pn-host', {'tokio-postgres'})
    if not driver_names:
        raise ValueError('host driver package identity missing')
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
        if re.search(r'\binclude\s*!',text):
            raise ValueError('production include is not an admitted module: '+relative)
        if relative == 'packages/host/src/storage.rs':
            continue
        if relative == 'packages/host/src/lib.rs':
            # Only the reviewed Session constructor may acquire the driver by inference.
            owner=re.search(r'\bimpl\s+Session\s*\{',text)
            if not owner:raise ValueError('Session constructor missing')
            start=re.search(r'\bpub\s+async\s+fn\s+connect\s*\(',text[owner.end():])
            if not start:raise ValueError('Session constructor missing')
            begin=owner.end()+start.start()
            opening=text.index('{',begin)
            depth=1;end=opening+1
            while depth and end<len(text):
                if text[end]=='{':depth+=1
                elif text[end]=='}':depth-=1
                end+=1
            if depth:raise ValueError('unclosed Session constructor')
            text=text[:begin]+' '*(end-begin)+text[end:]
        if any(re.search(r'\b'+re.escape(name)+r'\b',text) for name in driver_names):
            raise ValueError('driver path outside the closed statement wrapper and Session constructor: '+relative)
    return True
