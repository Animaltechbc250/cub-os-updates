"""Samsung native regression tests for declared/missing update directories."""
from pathlib import Path
import hashlib,importlib.util,json,os,subprocess,sys,zipfile

source,out=map(Path,sys.argv[1:]);out.mkdir(mode=0o700)
spec=importlib.util.spec_from_file_location('component',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
key=subprocess.run(['openssl','genpkey','-algorithm','ED25519'],capture_output=True,check=True).stdout
public=subprocess.run(['openssl','pkey','-pubout'],input=key,capture_output=True,check=True).stdout
passed=[]

def sign(raw):
    a=os.memfd_create('ephemeral-test-key',os.MFD_CLOEXEC);b=os.memfd_create('test-payload',os.MFD_CLOEXEC)
    try:
        os.write(a,key);os.write(b,raw);os.lseek(a,0,0);os.lseek(b,0,0)
        return subprocess.run(['openssl','pkeyutl','-sign','-inkey',f'/proc/self/fd/{a}','-rawin','-in',f'/proc/self/fd/{b}'],pass_fds=(a,b),capture_output=True,check=True).stdout
    finally:os.close(a);os.close(b)

def fixture(name):
    root=out/name;root.mkdir(mode=0o700)
    for rel in ['usr/local/share','usr/local/bin','usr/local/lib/cub-os','store']:(root/rel).mkdir(parents=True)
    return root

def make(root,change=None):
    data=b'new component bytes\n'
    v={'schema':1,'product':'cub-os','id':'directories-trial','title':'Directory support trial',
       'notes':'Create required folders safely, verify files and test rollback.','restart':'None.',
       'files':[{'path':'usr/local/share/cub-os/new/nested/component.txt','before':None,'bytes':len(data),'sha256':m.sha(data),'mode':0o644}]}
    if change:change(v)
    raw=m.canonical(v);p=root/'trial.zip'
    with zipfile.ZipFile(p,'x') as z:
        z.writestr('manifest.json',raw);z.writestr('manifest.sig',sign(raw));z.writestr('blobs/'+m.sha(data),data)
    return p,v,raw

def engine(root,report=lambda _:None):return m.Engine(root,root/'store',public,report=report)

def reject(name,call):
    before=len(os.listdir('/proc/self/fd'))
    try:call()
    except (ValueError,OSError):passed.append(name)
    else:raise AssertionError('Expected refusal: '+name)
    assert len(os.listdir('/proc/self/fd'))==before,'Descriptor leak: '+name

r=fixture('implicit');p,v,b=make(r);e=engine(r)
plan=e.preflight(v);assert len(plan['directories'])==3 and not (r/'usr/local/share/cub-os').exists()
passed.append('legacy signed file paths plan missing folders without creating them')
e.apply(p,m.sha(b));assert (r/v['files'][0]['path']).read_bytes()==b'new component bytes\n'
for entry in plan['directories']:assert (r/entry['path']).stat().st_mode&0o777==0o755
passed.append('real multi-level directory creation and payload install')
result=e.rollback(v['id']);assert not (r/'usr/local/share/cub-os').exists() and (r/'usr/local/share').is_dir()
passed.append('rollback removes only created empty directories; existing ancestor retained')

r=fixture('explicit');p,v,b=make(r,lambda v:v.update(directories=[{'path':'usr/local/share/cub-os/new','mode':0o700}]))
e=engine(r);e.apply(p,m.sha(b));assert (r/'usr/local/share/cub-os/new').stat().st_mode&0o777==0o700
e.rollback(v['id']);passed.append('genuinely signed explicit private directory mode and rollback')

r=fixture('existing');(r/'usr/local/share/cub-os').mkdir();p,v,b=make(r);e=engine(r);e.apply(p,m.sha(b));e.rollback(v['id'])
assert (r/'usr/local/share/cub-os').is_dir();passed.append('pre-existing component directory never removed')

r=fixture('owner-files');p,v,b=make(r);e=engine(r);e.apply(p,m.sha(b))
keep=r/'usr/local/share/cub-os/new/nested/owner-keep.txt';keep.write_bytes(b'keep me')
receipt=e.rollback(v['id']);assert keep.read_bytes()==b'keep me' and receipt['retained_directories']
assert not (r/v['files'][0]['path']).exists();passed.append('rollback preserves later files and their nonempty directories')

for name,change in [
    ('outside',lambda v:v.update(directories=[{'path':'etc/sudoers.d','mode':0o755}])),
    ('traversal',lambda v:v.update(directories=[{'path':'usr/local/share/cub-os/../evil','mode':0o755}])),
    ('writable',lambda v:v.update(directories=[{'path':'usr/local/share/cub-os','mode':0o777}])),
    ('duplicate',lambda v:v.update(directories=[{'path':'usr/local/share/cub-os','mode':0o755}]*2)),
    ('unused',lambda v:v.update(directories=[{'path':'usr/local/share/cub-os/unrelated','mode':0o755}]))]:
    r=fixture(name);p,v,b=make(r,change)
    reject('signed directory '+name+' refused',lambda:engine(r).apply(p,m.sha(b)))
    assert not (r/'usr/local/share/cub-os').exists()

r=fixture('symlink');outside=r/'outside';outside.mkdir();(r/'usr/local/share/cub-os').symlink_to(outside);p,v,b=make(r)
reject('symlink parent refused before any mkdir',lambda:engine(r).apply(p,m.sha(b)));assert list(outside.iterdir())==[]

r=fixture('file-parent');(r/'usr/local/share/cub-os').write_bytes(b'not a directory');p,v,b=make(r)
reject('regular file blocking parent refused',lambda:engine(r).apply(p,m.sha(b)))

r=fixture('mode-mismatch');(r/'usr/local/share/cub-os').mkdir(mode=0o700)
p,v,b=make(r,lambda v:v.update(directories=[{'path':'usr/local/share/cub-os','mode':0o755}]))
reject('existing directory permissions not silently changed',lambda:engine(r).apply(p,m.sha(b)))
assert (r/'usr/local/share/cub-os').stat().st_mode&0o777==0o700

r=fixture('bad-baseline');(r/'usr/local/lib/cub-os/existing.txt').write_bytes(b'owner data')
def bad_baseline(v):
    e=dict(v['files'][0]);e.update(path='usr/local/lib/cub-os/existing.txt',before={'sha256':'0'*64,'mode':0o644});v['files'].append(e)
p,v,b=make(r,bad_baseline)
reject('later file mismatch refuses before directory creation',lambda:engine(r).apply(p,m.sha(b)))
assert not (r/'usr/local/share/cub-os').exists()

r=fixture('download-error')
p,v,b=make(r,lambda v:v['files'][0].update(source='https://github.com/lonewolf0622/HelixSR/releases/download/v3.2.0/HelixSR-3.2.0.zip'))
real_fetch=m.fetch
def failure(*a,**k):raise OSError('Injected download failure')
m.fetch=failure
try:reject('download failure leaves new directories absent',lambda:engine(r).apply(p,m.sha(b)))
finally:m.fetch=real_fetch
assert not (r/'usr/local/share/cub-os').exists() and not (r/'store/directories-trial').exists()

r=fixture('directory-swap');p,v,b=make(r);e=engine(r);e.apply(p,m.sha(b))
target=r/'usr/local/share/cub-os/new/nested';target.rename(r/'saved-directory');target.mkdir()
reject('rollback holds changed directory identity',lambda:e.rollback(v['id']))
assert (r/'saved-directory/component.txt').read_bytes()==b'new component bytes\n'

r=fixture('mkdir-cut');p,v,b=make(r);pid=os.fork()
if pid==0:
    def stop(text):
        if text.startswith('Created directory '):os._exit(71)
    engine(r,stop).apply(p,m.sha(b));os._exit(99)
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==71
assert (r/'usr/local/share/cub-os').is_dir() and not (r/v['files'][0]['path']).exists()
engine(r).rollback(v['id']);assert not (r/'usr/local/share/cub-os').exists()
passed.append('actual process exit after mkdir; partial-directory transaction rolls back')

r=fixture('unproven-mkdir');p,v,b=make(r);pid=os.fork()
if pid==0:
    real=os.mkdir
    def stop(name,*a,**k):
        result=real(name,*a,**k)
        if name=='cub-os':os._exit(72)
        return result
    os.mkdir=stop
    engine(r).apply(p,m.sha(b));os._exit(99)
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==72
receipt=engine(r).rollback(v['id'])
assert (r/'usr/local/share/cub-os').is_dir() and receipt['retained_directories']==['usr/local/share/cub-os']
passed.append('crash before inode receipt preserves unproven directory rather than deleting it')

r=fixture('missing-installation');(r/'usr/local/share').rmdir();p,v,b=make(r)
reject('missing system ancestor outside component base refused',lambda:engine(r).apply(p,m.sha(b)))
assert not (r/'usr/local/share').exists()

result={'status':'native_directory_regressions_passed','count':len(passed),'passed':passed,
        'implementation_sha256':m.sha(source.read_bytes()),'installed_product_changed':False,
        'limits':['isolated native Btrfs fixtures; no physical power-loss claim','Lexar owner install not yet performed']}
(out/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
