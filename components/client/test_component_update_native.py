"""Native Linux tests: real signed bundles, filesystem writes and process exit.

Run on the Samsung dev system, passing the saved implementation path and a NEW
exclusive evidence directory. No installed product file is changed by this test.
"""
from pathlib import Path
import contextlib,fcntl,hashlib,importlib.util,io,json,os,subprocess,sys,zipfile

source,out=map(Path,sys.argv[1:]);out.mkdir(mode=0o700)
spec=importlib.util.spec_from_file_location('component',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.geteuid()==0
key=subprocess.run(['openssl','genpkey','-algorithm','ED25519'],capture_output=True,check=True).stdout
public=subprocess.run(['openssl','pkey','-pubout'],input=key,capture_output=True,check=True).stdout
passed=[]

def sign(raw):
    a=os.memfd_create('test-key',os.MFD_CLOEXEC);b=os.memfd_create('test-manifest',os.MFD_CLOEXEC)
    try:
        os.write(a,key);os.write(b,raw);os.lseek(a,0,0);os.lseek(b,0,0)
        return subprocess.run(['openssl','pkeyutl','-sign','-inkey',f'/proc/self/fd/{a}',
            '-rawin','-in',f'/proc/self/fd/{b}'],pass_fds=(a,b),capture_output=True,check=True).stdout
    finally:os.close(a);os.close(b)

def fixture(name):
    root=out/name;root.mkdir(mode=0o700)
    target=root/'usr/local/share/cub-os';target.mkdir(parents=True)
    (target/'existing.txt').write_bytes(b'old version\n');(target/'existing.txt').chmod(0o644)
    store=root/'store';store.mkdir(mode=0o700)
    return root,target,store

def make(root,identity='trial-one',change=None):
    target=root/'usr/local/share/cub-os'
    files=[];blobs={}
    for name,data in [('existing.txt',b'new version\n'),('added.txt',b'new file\n')]:
        p=target/name
        before={'sha256':m.sha(p.read_bytes()),'mode':p.stat().st_mode&0o777} if p.exists() else None
        files.append({'path':'usr/local/share/cub-os/'+name,'before':before,'sha256':m.sha(data),'bytes':len(data),'mode':0o644})
        blobs[m.sha(data)]=data
    value={'schema':1,'product':'cub-os','id':identity,'title':'Native component trial',
        'notes':'Replace one file and add another.\nTest rollback keeps unrelated files.',
        'restart':'No system restart required.','files':files}
    if change:change(value)
    raw=m.canonical(value);signature=sign(raw)
    path=root/(identity+'.zip')
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_STORED) as z:
        z.writestr('manifest.json',raw);z.writestr('manifest.sig',signature)
        for digest,data in blobs.items():z.writestr('blobs/'+digest,data)
    return path,value,raw

def expect(label,fn):
    try:fn()
    except (ValueError,OSError,KeyError,zipfile.BadZipFile):passed.append(label)
    else:raise AssertionError('Expected refusal: '+label)

def engine(root,store):return m.Engine(root,store,public,report=lambda text:None)

root,target,store=fixture('happy');package,value,raw=make(root)
beforefds=len(os.listdir('/proc/self/fd'))
text=io.StringIO()
with contextlib.redirect_stdout(text):m.show(value,raw)
assert value['notes'] in text.getvalue() and m.sha(raw) in text.getvalue();passed.append('notes and exact approval displayed')
e=engine(root,store)
expect('wrong approval held before target changes',lambda:e.apply(package,'0'*64))
assert (target/'existing.txt').read_bytes()==b'old version\n' and not (target/'added.txt').exists()
result=e.apply(package,m.sha(raw));assert result['phase']=='installed'
assert (target/'existing.txt').read_bytes()==b'new version\n' and (target/'added.txt').read_bytes()==b'new file\n'
passed.append('actual install replaces existing and creates new file')
expect('same ID cannot be reused',lambda:e.apply(package,m.sha(raw)))
result=e.rollback(value['id']);assert result['phase']=='rolled-back'
assert (target/'existing.txt').read_bytes()==b'old version\n' and not (target/'added.txt').exists()
passed.append('actual rollback restores old bytes and removes added file')
expect('rolled-back ID cannot be reused',lambda:e.apply(package,m.sha(raw)))
assert len(os.listdir('/proc/self/fd'))==beforefds;passed.append('descriptor cleanup success and refusal')

for name,change in [
    ('traversal',lambda v:v['files'][0].update(path='usr/local/share/cub-os/../../evil')),
    ('outside',lambda v:v['files'][0].update(path='etc/sudoers')),
    ('duplicate',lambda v:v['files'].append(dict(v['files'][0]))),
    ('mode',lambda v:v['files'][0].update(mode=0o4777)),
    ('no-notes',lambda v:v.update(notes='')),
    ('scripts-field',lambda v:v.update(postinstall='reboot')),
    ('oversize',lambda v:v['files'][0].update(bytes=m.MAX_FILE+1))]:
    r,t,s=fixture(name);p,v,b=make(r,change=change)
    expect('signed '+name+' refused',lambda:m.bundle(p,public))
    assert (t/'existing.txt').read_bytes()==b'old version\n'

r,t,s=fixture('baseline');p,v,b=make(r);(t/'existing.txt').write_bytes(b'owner edit')
expect('wrong installed baseline held',lambda:engine(r,s).apply(p,m.sha(b)))
assert list(s.iterdir())==[s/'worker.lock']

r,t,s=fixture('symlink');p,v,b=make(r);outside=r/'outside';outside.write_bytes(b'old version\n')
(t/'existing.txt').unlink();(t/'existing.txt').symlink_to(outside)
expect('symlink target held',lambda:engine(r,s).apply(p,m.sha(b)));assert outside.read_bytes()==b'old version\n'

r,t,s=fixture('hardlink');p,v,b=make(r);os.link(t/'existing.txt',r/'alias')
expect('hardlinked target held',lambda:engine(r,s).apply(p,m.sha(b)))

r,t,s=fixture('owner-change');p,v,b=make(r);e=engine(r,s);e.apply(p,m.sha(b));(t/'added.txt').write_bytes(b'owner change')
expect('rollback refuses owner changes before restoring any file',lambda:e.rollback(v['id']))
assert (t/'existing.txt').read_bytes()==b'new version\n'

r,t,s=fixture('backup-corrupt');p,v,b=make(r);e=engine(r,s);e.apply(p,m.sha(b));(s/v['id']/'backup-0').write_bytes(b'bad')
expect('rollback refuses corrupt backup before target changes',lambda:e.rollback(v['id']))
assert (t/'existing.txt').read_bytes()==b'new version\n'

r,t,s=fixture('lock');p,v,b=make(r)
with (s/'worker.lock').open('wb') as lock:
    lock.flush();os.chmod(lock.name,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    expect('concurrent kernel lock refused',lambda:engine(r,s).apply(p,m.sha(b)))

r,t,s=fixture('process-cut');p,v,b=make(r)
pid=os.fork()
if pid==0:
    count=[0]
    def progress(text):
        count[0]+=1
        if count[0]==2:os._exit(91)
    m.Engine(r,s,public,report=progress).apply(p,m.sha(b));os._exit(92)
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==91
assert (t/'existing.txt').read_bytes()==b'new version\n' and not (t/'added.txt').exists()
assert engine(r,s).rollback(v['id'])['phase']=='rolled-back'
assert (t/'existing.txt').read_bytes()==b'old version\n';passed.append('real child exit after first write; lock released and partial install rolled back')

r,t,s=fixture('signature');p,v,b=make(r)
bad=r/'bad.zip'
with zipfile.ZipFile(p) as a,zipfile.ZipFile(bad,'x') as z:
    for item in a.infolist():
        data=a.read(item)
        if item.filename=='manifest.sig':data=bytes([data[0]^1])+data[1:]
        z.writestr(item.filename,data)
expect('wrong signature refused',lambda:engine(r,s).apply(bad,m.sha(b)))
bad=r/'corrupt.zip'
with zipfile.ZipFile(p) as a,zipfile.ZipFile(bad,'x') as z:
    for item in a.infolist():
        data=a.read(item)
        if item.filename.startswith('blobs/'):data=b'X'*len(data)
        z.writestr(item.filename,data)
expect('actual archive payload corruption refused',lambda:engine(r,s).apply(bad,m.sha(b)))
assert (t/'existing.txt').read_bytes()==b'old version\n'
result={'status':'native_component_engine_tests_passed','passed':passed,'count':len(passed),
        'implementation_sha256':m.sha(source.read_bytes()),'installed_product_changed':False,
        'limits':['isolated directories on Samsung Btrfs; not a game test','no physical-power-loss claim','download/UI integration not tested here']}
(out/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
