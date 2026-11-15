"""Guard the raw-client type boundary; SQL admission is enforced by Rust types."""
from pathlib import Path
import re
import json
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
    pending=[(root/'packages/host/src/lib.rs',False)]
    pending.extend((path,True) for directory in ('tests','benches')
                   for path in (root/'packages/host'/directory).rglob('*.rs'))
    seen=set()
    while pending:
        path,test_only=pending.pop()
        if path in seen:continue
        seen.add(path)
        relative=path.relative_to(root).as_posix()
        source=path.read_text()
        full=rust_mask(source)
        text=' '*len(full) if test_only else production(source)
        if re.search(r'#\s*\[\s*path\s*=',text):
            raise ValueError('production module path needs reviewed traversal')
        test_paths={}
        for attribute in re.finditer(r'#\s*\[\s*path\s*=([^\]]+)\]\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:r#)?(\w+)\s*;',full):
            try:value=json.loads(source[attribute.start(1):attribute.end(1)].strip())
            except ValueError as error:raise ValueError('test module path is not a literal') from error
            target=(path.parent/value).resolve()
            if not target.is_relative_to((root/'packages/host').resolve()):
                raise ValueError('test module path leaves host package')
            test_paths[attribute.group(2)]=target.relative_to(root.resolve())
        directory=path.parent if path.name in ('lib.rs','mod.rs') else path.with_suffix('')
        for declaration in re.finditer(r'\bmod\s+(?:r#)?(\w+)\s*;',full):
            name=declaration.group(1)
            candidates=[root/test_paths[name]] if name in test_paths else [directory/(name+'.rs'),directory/name/'mod.rs']
            found=[p for p in candidates if p.exists()]
            if len(found)!=1:raise ValueError('ambiguous production module: '+relative+'::'+name)
            pending.extend((p,test_only or not text[declaration.start():declaration.end()].strip()) for p in found)
        if re.search(r'\binclude\s*!',full):
            raise ValueError('production include is not an admitted module: '+relative)
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
            full=full[:begin]+' '*(end-begin)+full[end:]
        if relative != 'packages/host/src/storage.rs' and any(re.search(r'\b'+re.escape(name)+r'\b',text) for name in driver_names):
            raise ValueError('driver path outside the closed statement wrapper and Session constructor: '+relative)
        # Retain test items here: they may use Session's client, never acquire a
        # real driver. The cancellation-token test's cancel_query_raw is not a
        # connection constructor. Config-only parsing tests remain admitted.
        constructors=re.sub(r'\b(?:Session|UnixStream|TcpStream)\s*::\s*connect\b','',full)
        if re.search(r'\b(?:connect_raw|connect)\b',constructors):
            raise ValueError('connection constructor outside Session, including test code: '+relative)
    return True
