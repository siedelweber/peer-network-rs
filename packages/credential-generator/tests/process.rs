use std::process::Command;

/// Fresh terminal processes deliver two exact ended streams, emit only public
/// JSON and trace content in default and trace modes, and return a nonzero public refusal without private
/// output for malformed metadata or a closed receiver. Receiver copies remain
/// in the external fixture process and are never printed or written to a file.
/// A full public-filled pipe remains unread through construction and termination;
/// the terminated process emits no success object and only well-formed JSON diagnostics.
/// # Panics
/// Panics if the runner omits the executable or a process violates the protocol.
/// ´claim:generator:process-delivery-keeps-private-streams-out-of-public-output´
/// ´test:integration:process-protocol´
#[test]
fn process_protocol() {
    let binary = std::path::PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_pn-credential-generator")
            .expect("runner must supply the credential generator executable at runtime"),
    );
    assert!(binary.is_absolute() && binary.is_file(), "runtime executable must exist");
    let output = Command::new("python3").args(["-c", launcher()]).arg(binary).output().unwrap();
    assert!(output.status.success(), "terminal process protocol: {output:?}");
    assert_eq!(
        output.stdout, b"process protocol passed\n",
        "only public fixture status returned"
    );
}

fn launcher() -> &'static str {
    r"
import os,sys,subprocess,json,fcntl,select,time,array,termios
binary=sys.argv[1]
child='''
import os,sys,fcntl
a=int(sys.argv[2]); b=int(sys.argv[3]); case=sys.argv[4]
x=fcntl.fcntl(a,fcntl.F_DUPFD_CLOEXEC,10); y=fcntl.fcntl(b,fcntl.F_DUPFD_CLOEXEC,10)
os.dup2(x,3); os.dup2(y,4)
for fd in set((a,b,x,y))-{3,4}: os.close(fd)
os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='2',LISTEN_FDNAMES='password:verifier',PN_OBSERVE_LEVEL='trace')
os.environ.pop('LISTEN_PIDFDID',None)
if case=='missing': os.environ['LISTEN_FDS']='1'
if case=='reverse': os.environ['LISTEN_FDNAMES']='verifier:password'
if case=='default': os.environ.pop('PN_OBSERVE_LEVEL',None)
os.execv(sys.argv[1],[sys.argv[1]])
'''
def wait_output(process):
    try: return process.communicate(timeout=600)
    except subprocess.TimeoutExpired: raise TimeoutError('HANG awaiting generator process exit and output drain; last state=child-pending') from None
def wait_exit(process):
    try: return process.wait(timeout=600)
    except subprocess.TimeoutExpired: raise TimeoutError('HANG awaiting killed generator process; last state=child-pending') from None
for case in ('normal','reverse','default','missing','closed'):
    ar,aw=os.pipe(); br,bw=os.pipe()
    if case=='closed': os.close(ar); ar=None
    p=None
    try:
        p=subprocess.Popen([sys.executable,'-c',child,binary,str(aw),str(bw),case],pass_fds=(aw,bw),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        os.close(aw); aw=None; os.close(bw); bw=None
        out,err=wait_output(p)
        a=os.read(ar,1024) if ar is not None else b''; b=os.read(br,1024)
        assert (ar is None or os.read(ar,1)==b'') and os.read(br,1)==b'', 'both private streams ended after exit'
        password,verifier=(b,a) if case=='reverse' else (a,b)
        if case in ('normal','reverse','default'):
            assert p.returncode==0, 'terminal success status'
            assert len(password)==64 and len(verifier)==135, 'exact protected delivery lengths'
            assert json.loads(out)==dict(locked_pages=2,password_bytes=64,verifier_bytes=135), 'public success fields'
        else:
            assert p.returncode==1 and out==b'', 'nonzero refusal has no success object'
            if case=='missing': assert not a and not b, 'metadata refusal precedes entropy output'
            else: assert len(b)==135, 'other delivery survives closed first reader'
        for private in (password,verifier):
            if private:
                assert private not in out+err, 'private text absent from public output'
                assert str(list(private)).encode() not in out+err, 'private byte list absent from public output'
        if case in ('normal','reverse','default'):
            if case=='default':
                assert b'generator__root__dec__observe__first_start_route__started_operations' in err, ('registered generator metric observed',case,err.decode(errors='replace'))
            else:
                assert b'GENERATOR' in err and b'dec:observe:first-start-route' in err, ('registered generator trace observed',case,err.decode(errors='replace'))
        for line in err.splitlines(): json.loads(line)
    finally:
        if p is not None and p.poll() is None: p.kill(); wait_exit(p)
        for fd in (ar,aw,br,bw):
            if fd is not None: os.close(fd)
ar,aw=os.pipe(); br,bw=os.pipe(); p=None
try:
    capacity=fcntl.fcntl(aw,fcntl.F_GETPIPE_SZ)
    assert os.write(aw,b'Z'*capacity)==capacity, 'fixture fills the entire pipe'
    p=subprocess.Popen([sys.executable,'-c',child,binary,str(aw),str(bw),'normal'],pass_fds=(aw,bw),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    os.close(aw); aw=None; os.close(bw); bw=None
    diagnostic=b''; ready=False; construction=None; deadline=time.monotonic()+600
    while p.poll() is None:
        if time.monotonic()>=deadline: raise TimeoutError('HANG awaiting protected-construction event')
        readable,_,_=select.select([p.stderr],[],[],0.1)
        if readable:
            diagnostic+=os.read(p.stderr.fileno(),65536)
            for line in diagnostic.splitlines():
                try: event=json.loads(line)
                except ValueError: continue
                detail=event.get('detail',{})
                if detail.get('arguments',{}).get('source_item')=='Protection::credential':
                    construction=event.get('operation_id')
                if construction is not None and event.get('operation_id')==construction and event.get('event_kind')=='completion' and detail.get('outcome')=='success':
                    ready=True
        if ready: break
    if not ready or p.poll() is not None:
        out,err=wait_output(p)
        raise AssertionError(('construction event absent',p.returncode,out,diagnostic+err))
    count=array.array('i',[0]); fcntl.ioctl(ar,termios.FIONREAD,count,True)
    assert count[0]==capacity, 'reader retains the full pipe before termination'
    p.terminate(); out,err=wait_output(p); err=diagnostic+err
    assert p.returncode!=0 and out==b'', 'terminated full-pipe process has no success object'
    for line in err.splitlines(): json.loads(line)
    assert b'password_bytes' not in out and b'verifier_bytes' not in out, 'termination publishes no success fields'
    assert os.read(ar,capacity)==b'Z'*capacity and os.read(ar,1)==b'', 'no protected byte entered the full pipe'
    assert os.read(br,1)==b'', 'termination precedes the verifier delivery'
finally:
    if p is not None and p.poll() is None: p.kill(); wait_exit(p)
    for fd in (ar,aw,br,bw):
        if fd is not None: os.close(fd)
print('process protocol passed')
"
}
