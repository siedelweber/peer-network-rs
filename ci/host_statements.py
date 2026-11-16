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
    pending=[(root/'packages/host/src/lib.rs',False,False)]
    pending.extend((path,True,False) for directory in ('tests','benches')
                   for path in (root/'packages/host'/directory).rglob('*.rs'))
    seen=set()
    fixture_sources={}
    while pending:
        path,test_only,fixture=pending.pop()
        visit=(path,fixture)
        if visit in seen:continue
        seen.add(visit)
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
            pending.extend((p,test_only or not text[declaration.start():declaration.end()].strip(),
                            fixture or (relative=='packages/host/src/lib.rs' and name=='credential_fixture')) for p in found)
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
        # The fixture witnesses the host transport; other tests may acquire
        # their own disposable connections. Production keeps its masked check.
        constructors=re.sub(r'\b(?:Session|UnixStream|TcpStream)\s*::\s*connect\b','',full if fixture else text)
        if re.search(r'\b(?:connect_raw|connect)\b',constructors):
            message=('connection constructor outside Session in the credential fixture: '
                     if fixture else 'connection constructor outside Session in production: ')
            raise ValueError(message+relative)
        if fixture:
            public_statements(source,relative)
            fixture_sources[relative]=source
            # Closed lexical call shapes; the bindings and interpreter payload
            # remain reviewed, rather than inferred by this source check.
            admitted={'interpreter', 'program', '&programs[0]',
                      'std::env::current_exe().unwrap()'}
            for launch in re.finditer(r'\bCommand\s*::\s*new\s*\(',full):
                begin=launch.end();end=begin;depth=1
                while depth and end<len(full):
                    if full[end]=='(':depth+=1
                    elif full[end]==')':depth-=1
                    end+=1
                argument=re.sub(r'\s+', '', source[begin:end-1])
                if depth or argument not in admitted:
                    raise ValueError('launch outside credential fixture lexical roster: '+relative)
    fixture_contract(root,fixture_sources)
    return True


def separated(source):
    """Split a lexical argument list, retaining string bytes for admission."""
    mask=rust_mask(source);depth=0;start=0;parts=[]
    for i,char in enumerate(mask):
        if char in '([{':depth+=1
        elif char in ')]}':depth-=1
        elif char==',' and depth==0:parts.append(source[start:i].strip());start=i+1
    parts.append(source[start:].strip())
    return [part for part in parts if part]


def enclosure(source,start):
    mask=rust_mask(source);opening=mask[start];closing={'(':')','[':']','{':'}'}[opening]
    depth=1;end=start+1
    while depth and end<len(mask):
        if mask[end]==opening:depth+=1
        elif mask[end]==closing:depth-=1
        end+=1
    if depth:raise ValueError('credential statement source has an unclosed expression')
    return source[start+1:end-1],end


def public_statements(source,path):
    """Admit public statement expressions; no binding-name exemption."""
    mask=rust_mask(source)
    constants=set()
    for declaration in re.finditer(r'\bconst\s+([A-Z][A-Z_0-9]*)\s*:',mask):
        start=mask.index('=',declaration.end())+1;end=mask.index(';',start)
        value=source[start:end].strip()
        if not re.search(r'\b[A-Za-z_]\w*\b',rust_mask(value)):
            constants.add(declaration[1])
    def public(value,bindings):
        value=value.strip().removeprefix('&').strip()
        if value in constants or value in bindings:return True
        if re.fullmatch(r'"(?:[^"\\]|\\.)*"|r"[\s\S]*"',value):return True
        if value.startswith('format!(') and value.endswith(')'):
            args=separated(value[8:-1])
            if not args or not re.fullmatch(r'"(?:[^"\\]|\\.)*"',args[0]):return False
            names=re.findall(r'(?<!\{)\{([A-Za-z_]\w*)(?::[^}]*)?\}(?!\})',args[0])
            return all(public(name,bindings) for name in names) and all(public(arg,bindings) for arg in args[1:])
        call=re.fullmatch(r'(literal|setting)\((.*)\)',value,re.S)
        if call:return all(public(arg,bindings) for arg in separated(call[2]))
        replaced=re.fullmatch(r'(.*)\.replace\((.*)\)',value,re.S)
        if replaced:return public(replaced[1],bindings) and all(public(arg,bindings) for arg in separated(replaced[2]))
        return bool(re.fullmatch(r'(?:Inventory::[A-Z]\w*|row)\.(?:predicate|recorded)\(\)',re.sub(r'\s+','',value)) and ('row' in bindings or value.startswith('Inventory::')))
    for function in re.finditer(r'\b(?:async\s+)?fn\s+(\w+)\s*\(',mask):
        opening=mask.find('{',function.end())
        if opening<0:continue
        body,_=enclosure(source,opening);code=rust_mask(body);bindings=set();loops=[]
        # These arguments flow only from the checked call sites below. Their
        # fixed helper definitions are checked separately, not inferred by name.
        if function[1]=='require':
            expected='if !self.query(&format!("SELECT ({predicate}) IS TRUE AS ok"), true).await? { return Err(Refusal::Inventory); } Ok(())'
            if re.sub(r'\s+','',body)!=re.sub(r'\s+','',expected):
                raise ValueError('credential public predicate forwarding differs: '+path)
            bindings.add('predicate')
        for loop in re.finditer(r'\bfor\s+(\([^)]*\)|\w+)\s+in\s+',code):
            begin=loop.end();finish=code.find('{',begin)
            expression=body[begin:finish].strip()
            names=set(re.findall(r'\b[a-z_]\w*\b',loop[1]))
            literal_rows=expression.startswith('[') and not re.search(r'\b[A-Za-z_]\w*\b',rust_mask(expression))
            constant_rows=re.fullmatch(r"([A-Z][A-Z_0-9]*)\.split\(','\)",expression)
            constant_rows=bool(constant_rows and constant_rows[1] in constants)
            if constant_rows or literal_rows or expression=='SUPPRESSIONS' or expression=='profile.settings()' or (expression=='INVENTORY' and names=={'row'}):
                _,end=enclosure(body,finish)
                loops.append((finish,end,names))
        for call in re.finditer(r'(?:\.\s*(query|require|rows)|RawSession\s*::\s*(query|require|rows))\s*\(',code):
            visible=bindings.copy()
            for begin,end,names in loops:
                if begin<call.start()<end:visible.update(names)
            # Shadowed or reassigned locals never inherit a loop's public origin.
            for binding in tuple(visible):
                if re.search(r'\blet\s+(?:mut\s+)?'+re.escape(binding)+r'\b|(?<![.=])\b'+re.escape(binding)+r'\s*=(?!=)',code):
                    visible.remove(binding)
            arguments,_=enclosure(body,call.end()-1)
            args=separated(arguments)
            argument=1 if call[2] else 0
            if len(args)<=argument or not public(args[argument],visible):
                raise ValueError('credential statement text is not a literal or public constant formatting: '+path)


def fixture_contract(root,sources):
    """Join planned fixture exits and pin the public helper and handoff source."""
    template=(root/'docs/templates/adr/016-observability.md.j2').read_text()
    planned={name for cell in re.findall(r'^\| (cav:observe:secret-host-credential-[^|]+)\|',template,re.M)
             for name in re.findall(r'cav:observe:secret-host-credential-[a-z0-9-]+',cell)}
    if len(planned)!=14:raise ValueError('credential planned exit inventory differs')
    from discipline import exposure_sites
    present=set()
    site_count=0
    for path,source in sources.items():
        sites,findings=exposure_sites(path,source)
        site_count+=len(sites)
        if findings:raise ValueError('credential fixture exit inventory malformed')
        present.update(site['label'] for site in sites)
    if present-planned:raise ValueError('credential fixture exit outside planned inventory')
    wrapper=sources['packages/host/src/credential_fixture.rs']
    if wrapper.count('pass_fds=(a,b)')!=1 or wrapper.count('os.close(a);os.close(b)')!=1:
        raise ValueError('credential wrapper descriptor handoff differs')
    raw=sources.get('packages/host/src/credential_fixture/raw.rs','')
    if not raw:raise ValueError('credential raw fixture module missing')
    helper=re.search(r'const HELPER_BODY: &str = r"(.*?)";',raw,re.S)
    if helper is None or helper[1]!=HELPER_BODY:
        raise ValueError('credential helper source differs from fixed public form')
    code=rust_mask(raw)
    variants=re.search(r'enum Inventory\s*\{([^}]+)\}',code,re.S)
    roster=re.search(r'const INVENTORY[^=]*=\s*\[([^;]+)\];',code,re.S)
    if variants is None or roster is None:
        raise ValueError('credential inventory closed roster missing')
    names=re.findall(r'\b([A-Z]\w*)\b',variants[1])
    rows=re.findall(r'Inventory::(\w+)',roster[1])
    if len(names)!=31 or sorted(names)!=sorted(rows) or len(set(rows))!=31:
        raise ValueError('credential inventory closed roster differs')
    print(f'HOST-CREDENTIAL-EXITS sites={site_count} labels={len(present)} planned={len(planned)} findings=0 names='+','.join(sorted(present)))
    return present

HELPER_BODY = "BEGIN\nIF $1 IS NULL OR pg_catalog.octet_length($1) <> 135 OR $1 !~ '^SCRAM-SHA-256[$]600000:[A-Za-z0-9+/]{22}==[$][A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$' THEN\nRAISE EXCEPTION USING MESSAGE = 'credential framing refused', ERRCODE = '22023';\nEND IF;\nEXECUTE 'ALTER ROLE credential_target PASSWORD ' || pg_catalog.quote_literal($1);\nEND"
