#!/usr/bin/python3 -I
"""Signed, local component bundles; no installer hooks, package manager or reboot.

CLI trust is the existing Cub beta public key. Developers can test Engine with
an isolated root and ephemeral public key; the installed CLI exposes neither.
"""
import argparse
import base64
import contextlib
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import uuid
import zipfile
import ssl
import urllib.request
import urllib.parse

KEY = Path('/etc/cub-os/beta-update-public.pem')
STORE = Path('/var/lib/cub-os/component-updates')
PREFIXES = ('usr/local/lib/cub-os/', 'usr/local/share/cub-os/',
            'usr/local/bin/cub-helixsr-setup',
            'usr/share/steam/compatibilitytools.d/proton-cachyos-slr-bc250/',
            'etc/NetworkManager/conf.d/', 'etc/gamescope-session-plus/sessions.d/')
MAX_FILE = 256 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_FILES = 128
MAX_DIRECTORIES = 256
DIRECTORY_BASES = tuple(p.rstrip('/') for p in PREFIXES if p.endswith('/'))
CHANNEL = 'https://raw.githubusercontent.com/Animaltechbc250/cub-os-updates/main/components/channel.json'


def approved_url(url):
    require(type(url) is str and len(url) < 2048, 'Download URL')
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and not parsed.username and not parsed.password and
            not parsed.query and not parsed.fragment and parsed.port is None, 'HTTPS source required')
    require(url.startswith('https://raw.githubusercontent.com/Animaltechbc250/cub-os-updates/main/components/') or
            url == 'https://github.com/lonewolf0622/HelixSR/releases/download/v3.2.0/HelixSR-3.2.0.zip',
            'Download source not approved')
    return url


def fetch(url, maximum, expected=None):
    approved_url(url)
    class Redirect(urllib.request.HTTPRedirectHandler):
        count = 0
        def redirect_request(self, request, fp, code, message, headers, target):
            self.count += 1
            p = urllib.parse.urlsplit(target)
            require(self.count <= 3 and p.scheme == 'https' and not p.username and
                    not p.password and p.hostname in ('release-assets.githubusercontent.com',
                    'objects.githubusercontent.com', 'raw.githubusercontent.com') and
                    p.port is None and not p.fragment, 'Download redirect refused')
            return urllib.request.Request(target, headers={'User-Agent': 'Cub-Component-Updater/1'})
    ca = Path('/etc/ca-certificates/extracted/tls-ca-bundle.pem')
    with directory(ca.parent) as fd:
        read_at(fd, ca.name, 1024**2)
    context = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), Redirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'Cub-Component-Updater/1',
        'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache'})
    start = time.monotonic()
    data = bytearray()
    with opener.open(request, timeout=20) as response:
        require(response.status == 200 and response.headers.get('Content-Encoding', 'identity') == 'identity',
                'Unexpected download response')
        while True:
            require(time.monotonic() - start < 480, 'Download deadline')
            block = response.read(min(1024**2, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            require(len(data) <= maximum, 'Download size bound')
    if expected is not None:
        require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'Download checksum mismatch')
    return bytes(data)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def parse(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, 'Duplicate JSON field')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON number')))


def trusted(info):
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'Untrusted owner or permissions')


@contextlib.contextmanager
def directory(path):
    """Walk from / with held nofollow FDs, rejecting nested devices."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute safe directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        trusted(os.fstat(fd))
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            try:
                trusted(os.fstat(child))
                require(os.fstat(fd).st_dev == os.fstat(child).st_dev, 'Nested filesystem refused')
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def read_at(fd, name, maximum=MAX_FILE):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        before = os.fstat(handle)
        trusted(before)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
                'Regular, single-link bounded file required')
        data = bytearray()
        while True:
            block = os.read(handle, min(1024**2, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            require(len(data) <= maximum, 'File size bound')
        after = os.fstat(handle)
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'File changed')
        return bytes(data), stat.S_IMODE(before.st_mode)
    finally:
        os.close(handle)


def snapshot(fd, name):
    try:
        data, mode = read_at(fd, name)
        return {'sha256': sha(data), 'mode': mode}, data
    except FileNotFoundError:
        return None, None


def atomic(fd, name, data, mode):
    temporary = '.cub-component-' + uuid.uuid4().hex
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode, dir_fd=fd)
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    except BaseException:
        # Retain a partial after a real write/fsync failure for diagnosis.
        raise


def verify_signature(raw, signature, key):
    require(len(signature) == 64, 'Exact Ed25519 signature required')
    # Only public metadata is stored here, with private directory permissions.
    with tempfile.TemporaryDirectory(prefix='cub-component-signature-') as folder:
        folder = Path(folder)
        (folder / 'public.pem').write_bytes(key)
        (folder / 'manifest').write_bytes(raw)
        (folder / 'signature').write_bytes(signature)
        algorithm = subprocess.run(['/usr/bin/openssl', 'pkey', '-pubin', '-inform', 'PEM',
                                    '-outform', 'DER'], input=key, capture_output=True, timeout=5)
        require(algorithm.returncode == 0 and len(algorithm.stdout) == 44 and
                algorithm.stdout.startswith(bytes.fromhex('302a300506032b6570032100')),
                'Ed25519 public key required')
        p = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin',
                            '-inkey', str(folder / 'public.pem'), '-rawin',
                            '-in', str(folder / 'manifest'), '-sigfile', str(folder / 'signature')],
                           capture_output=True, timeout=10,
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        require(p.returncode == 0, 'Publisher signature rejected')


def manifest(raw, signature, key):
    require(len(raw) <= 128 * 1024, 'Manifest size bound')
    verify_signature(raw, signature, key)
    value = parse(raw)
    fields = {'schema', 'product', 'id', 'title', 'notes', 'restart', 'files'}
    require(type(value) is dict and set(value) in (fields, fields | {'directories'}), 'Manifest fields')
    require(canonical(value) == raw, 'Canonical signed manifest required')
    require(type(value['schema']) is int and value['schema'] == 1 and value['product'] == 'cub-os',
            'Wrong schema or product')
    require(type(value['id']) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}', value['id'])
            and '..' not in value['id'], 'Update ID')
    for field, bound in [('title', 160), ('notes', 12000), ('restart', 500)]:
        require(type(value[field]) is str and 0 < len(value[field]) <= bound and
                all(ord(c) >= 32 or c in '\n\t' for c in value[field]), 'Release text bound')
    require(type(value['files']) is list and 0 < len(value['files']) <= MAX_FILES, 'File list bound')
    seen = set()
    total = 0
    for entry in value['files']:
        require(type(entry) is dict and set(entry) in ({'path', 'before', 'sha256', 'bytes', 'mode'},
                {'path', 'before', 'sha256', 'bytes', 'mode', 'source'}),
                'File descriptor fields')
        path = entry['path']
        require(type(path) is str and len(path) <= 240 and str(PurePosixPath(path)) == path and
                not path.startswith('/') and '\\' not in path and
                all(p not in ('', '.', '..') and not p.startswith('.') for p in path.split('/')) and
                (path.startswith(tuple(p for p in PREFIXES if p.endswith('/'))) or
                 path == 'usr/local/bin/cub-helixsr-setup'), 'Target not allowlisted')
        require(path not in seen, 'Duplicate target')
        seen.add(path)
        require(type(entry['mode']) is int and entry['mode'] in (0o644, 0o755), 'Target mode')
        require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= MAX_FILE, 'Payload size')
        require(type(entry['sha256']) is str and re.fullmatch('[a-f0-9]{64}', entry['sha256']), 'Payload hash')
        if 'source' in entry:
            approved_url(entry['source'])
        before = entry['before']
        if before is not None:
            require(type(before) is dict and set(before) == {'sha256', 'mode'} and
                    type(before['sha256']) is str and re.fullmatch('[a-f0-9]{64}', before['sha256']) and
                    type(before['mode']) is int and before['mode'] in (0o644, 0o755), 'Before descriptor')
        total += entry['bytes']
    require(total <= MAX_TOTAL, 'Total payload size')
    require(not any(a != b and b.startswith(a + '/') for a in seen for b in seen),
            'A file cannot also be a parent directory')
    dirs = value.get('directories', [])
    require(type(dirs) is list and len(dirs) <= MAX_DIRECTORIES, 'Directory list bound')
    declared = set()
    for entry in dirs:
        require(type(entry) is dict and set(entry) == {'path', 'mode'}, 'Directory descriptor fields')
        path = entry['path']
        require(safe_directory(path) and path not in declared and path not in seen and
                any(f.startswith(path + '/') for f in seen), 'Unapproved or unused directory declaration')
        require(type(entry['mode']) is int and entry['mode'] in (0o700, 0o755), 'Directory mode')
        declared.add(path)
    return value


def safe_directory(path):
    return (type(path) is str and 0 < len(path) <= 240 and
            str(PurePosixPath(path)) == path and not path.startswith('/') and '\\' not in path and
            len(path.split('/')) <= 24 and
            all(p not in ('', '.', '..') and not p.startswith('.') for p in path.split('/')) and
            any(path == base or path.startswith(base + '/') for base in DIRECTORY_BASES))


def bundle(path, key, download=False, report=print):
    # Open once, never execute or extract archive paths to the filesystem.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_TOTAL + 1024**2, 'Bundle size/type')
        with zipfile.ZipFile(stream) as archive:
            items = archive.infolist()
            names = [i.filename for i in items]
            require(len(names) == len(set(names)) and len(names) <= MAX_FILES + 2, 'Duplicate/excess archive members')
            require(all(not i.flag_bits & 1 for i in items), 'Encrypted archive refused')
            require(archive.getinfo('manifest.json').file_size <= 128 * 1024 and
                    archive.getinfo('manifest.sig').file_size == 64, 'Manifest archive bounds')
            raw, signature = archive.read('manifest.json'), archive.read('manifest.sig')
            value = manifest(raw, signature, key)
            expected = {'manifest.json', 'manifest.sig'} | {'blobs/' + e['sha256'] for e in value['files'] if 'source' not in e}
            require(set(names) == expected, 'Unexpected or missing archive member')
            blobs = {}
            for entry in value['files']:
                if 'source' in entry:
                    if download:
                        report('Downloading and checking ' + entry['path'])
                        blobs[entry['sha256']] = fetch(entry['source'], entry['bytes'], entry)
                    continue
                name = 'blobs/' + entry['sha256']
                require(archive.getinfo(name).file_size == entry['bytes'], 'Archive file size')
                data = archive.read(name)
                require(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'Corrupt payload')
                blobs[entry['sha256']] = data
    return value, raw, signature, blobs


@contextlib.contextmanager
def channel_bundle():
    outer = parse(fetch(CHANNEL, 2 * 1024**2))
    require(type(outer) is dict and set(outer) == {'bundle'}, 'Channel fields')
    data = base64.b64decode(outer['bundle'], validate=True)
    require(len(data) <= 1024**2, 'Channel bundle bound')
    with tempfile.TemporaryDirectory(prefix='cub-component-channel-') as folder:
        path = Path(folder) / 'update.zip'
        path.write_bytes(data)
        yield path


def show(value, raw):
    print(value['title'] + '\n\n' + value['notes'] + '\n\nRestart: ' + value['restart'], flush=True)
    print('\nFiles: ' + str(len(value['files'])) + '\nApproval SHA256: ' + sha(raw), flush=True)


class Engine:
    def __init__(self, root, store, key, report=print):
        self.root, self.store, self.key, self.report = Path(root), Path(store), key, report

    @contextlib.contextmanager
    def locked(self):
        require(os.geteuid() == 0, 'Administrator access is required to install or roll back')
        # Store must be provisioned by the trusted tool installation, not a bundle.
        with directory(self.store) as fd:
            lock = os.open('worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                trusted(os.fstat(lock))
                require(stat.S_ISREG(os.fstat(lock).st_mode) and os.fstat(lock).st_nlink == 1, 'Lock identity')
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield fd
            finally:
                os.close(lock)

    @contextlib.contextmanager
    def targets(self, entries):
        with contextlib.ExitStack() as stack:
            result = []
            for e in entries:
                path = self.root / e['path']
                fd = stack.enter_context(directory(path.parent))
                result.append((e, fd, path.name))
            yield result

    def journal(self, fd, value):
        atomic(fd, 'receipt.json', canonical(value), 0o600)

    def target_state(self, entry):
        path = self.root / entry['path']
        try:
            with directory(path.parent) as fd:
                return snapshot(fd, path.name)
        except FileNotFoundError:
            return None, None

    def preflight(self, value):
        """Read-only plan. Signed file parents imply 0755 for legacy bundles.

        Explicit signed directory descriptors may request 0700 or 0755. Only
        directories inside the fixed component bases can ever be created.
        Missing installation ancestors outside those bases are an incompatibility.
        """
        modes = {e['path']: e['mode'] for e in value.get('directories', [])}
        missing, existing = {}, {}
        for entry in value['files']:
            parts = PurePosixPath(entry['path']).parent.parts
            with directory(self.root) as root:
                fd = os.dup(root)
                absent = False
                try:
                    for index, name in enumerate(parts):
                        relative = '/'.join(parts[:index + 1])
                        if not absent:
                            try:
                                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                dir_fd=fd)
                            except FileNotFoundError:
                                absent = True
                            except OSError as error:
                                raise ValueError('Cannot use directory ' + str(self.root / relative) + ': ' + error.strerror) from error
                            else:
                                try:
                                    info = os.fstat(child)
                                    trusted(info)
                                    require(info.st_dev == os.fstat(fd).st_dev, 'Nested filesystem refused')
                                    if relative in modes:
                                        require(stat.S_IMODE(info.st_mode) == modes[relative],
                                                'Existing directory mode differs: ' + relative)
                                    existing[relative] = [info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)]
                                except BaseException:
                                    os.close(child)
                                    raise
                                os.close(fd)
                                fd = child
                        if absent:
                            require(safe_directory(relative), 'Missing installation directory outside update scope: ' + relative)
                            missing[relative] = modes.get(relative, 0o755)
                finally:
                    os.close(fd)
        require(len(missing) <= MAX_DIRECTORIES, 'Too many new directories')
        before_bytes = 0
        for entry in value['files']:
            current, data = self.target_state(entry)
            require(current == entry['before'], 'Installed file differs: ' + entry['path'])
            before_bytes += len(data) if data is not None else 0
        return {'directories': [{'path': p, 'mode': missing[p]} for p in sorted(missing, key=lambda p: (len(p.split('/')), p))],
                'existing': existing, 'backup_bytes': before_bytes}

    def create_directories(self, tx, record, plan):
        for entry in plan['directories']:
            path = self.root / entry['path']
            # Persist intent before mkdir. A crash before inode recording keeps
            # the unproven directory for inspection; rollback never guesses ownership.
            saved = {'path': entry['path'], 'mode': entry['mode'], 'identity': None}
            record['created_directories'].append(saved)
            self.journal(tx, record)
            with directory(path.parent) as fd:
                os.mkdir(path.name, entry['mode'], dir_fd=fd)
                os.fsync(fd)
            with directory(path) as fd:
                os.fchmod(fd, entry['mode'])
                os.fsync(fd)
                info = os.fstat(fd)
                require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == entry['mode'], 'New directory metadata')
                saved['identity'] = [info.st_dev, info.st_ino]
            self.journal(tx, record)
            self.report('Created directory ' + entry['path'])

    def validate_created_directories(self, record, value):
        created = record.get('created_directories', [])
        require(type(created) is list and len(created) <= MAX_DIRECTORIES, 'Retained directory list')
        seen = set()
        for item in created:
            require(type(item) is dict and set(item) == {'path', 'mode', 'identity'} and
                    safe_directory(item['path']) and item['path'] not in seen and
                    any(e['path'].startswith(item['path'] + '/') for e in value['files']) and
                    type(item['mode']) is int and item['mode'] in (0o700, 0o755), 'Retained directory descriptor')
            seen.add(item['path'])
            identity = item['identity']
            require(identity is None or (type(identity) is list and len(identity) == 2 and
                    all(type(n) is int and n >= 0 for n in identity)), 'Directory identity')
            if identity is not None:
                try:
                    with directory(self.root / item['path']) as fd:
                        info = os.fstat(fd)
                        require([info.st_dev, info.st_ino] == identity and
                                stat.S_IMODE(info.st_mode) == item['mode'], 'Created directory changed; rollback held')
                except FileNotFoundError:
                    pass
        return created

    def remove_created_directories(self, created):
        retained = []
        for item in sorted(created, key=lambda e: len(e['path'].split('/')), reverse=True):
            path = self.root / item['path']
            try:
                with directory(path) as fd:
                    info = os.fstat(fd)
                    if item['identity'] is None:
                        retained.append(item['path'])
                        continue
                    require([info.st_dev, info.st_ino] == item['identity'], 'Directory changed during rollback')
                with directory(path.parent) as fd:
                    try:
                        os.rmdir(path.name, dir_fd=fd)
                    except OSError as error:
                        if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                            raise
                        retained.append(item['path'])
                    os.fsync(fd)
            except FileNotFoundError:
                pass
        for path in retained:
            self.report('Retained nonempty or unproven directory ' + path)
        return retained

    def apply(self, package, approval):
        value, raw, signature, blobs = bundle(package, self.key)
        require(approval == sha(raw), 'Inspect the update notes and supply their exact approval hash')
        with self.locked() as store:
            try:
                os.stat(value['id'], dir_fd=store, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('This update ID has a retained transaction; inspect it before another attempt')
            plan = self.preflight(value)
            required = 2 * sum(e['bytes'] for e in value['files']) + plan['backup_bytes'] + 64 * 1024**2
            fs = os.fstatvfs(store)
            require(fs.f_bavail * fs.f_frsize >= required, 'Insufficient free space')
            # Fetch only authenticated descriptors, after installed-baseline checks.
            _, checked_raw, _, blobs = bundle(package, self.key, download=True, report=self.report)
            require(checked_raw == raw, 'Bundle changed during preparation')
            require(self.preflight(value) == plan, 'Installation paths changed during preparation')
            fs = os.fstatvfs(store)
            require(fs.f_bavail * fs.f_frsize >= required, 'Insufficient free space')
            # No replacement/reuse of retained transaction IDs, including failed ones.
            os.mkdir(value['id'], 0o700, dir_fd=store)
            os.fsync(store)
            with directory(self.store / value['id']) as tx:
                atomic(tx, 'manifest.json', raw, 0o600)
                atomic(tx, 'manifest.sig', signature, 0o600)
                record = {'schema': 1, 'id': value['id'], 'manifest_sha256': sha(raw),
                          'phase': 'backing-up', 'installed_count': 0, 'time': int(time.time()),
                          'created_directories': []}
                self.journal(tx, record)
                try:
                    for i, e in enumerate(value['files']):
                        before, data = self.target_state(e)
                        require(before == e['before'], 'File changed before backup')
                        if data is not None:
                            atomic(tx, 'backup-' + str(i), data, 0o600)
                    record['phase'] = 'preparing-directories'
                    self.journal(tx, record)
                    self.create_directories(tx, record, plan)
                    with self.targets(value['files']) as targets:
                        for e, fd, name in targets:
                            require(snapshot(fd, name)[0] == e['before'], 'File changed before replacement')
                        record['phase'] = 'installing'
                        self.journal(tx, record)
                        for i, (e, fd, name) in enumerate(targets):
                            require(snapshot(fd, name)[0] == e['before'], 'File changed before replacement')
                            self.report('Installing ' + e['path'])
                            atomic(fd, name, blobs[e['sha256']], e['mode'])
                            require(snapshot(fd, name)[0] == {'sha256': e['sha256'], 'mode': e['mode']},
                                    'Written file verification failed')
                            record['installed_count'] = i + 1
                            self.journal(tx, record)
                    record['phase'] = 'installed'
                    self.journal(tx, record)
                except BaseException:
                    record['phase'] = 'failed-retained'
                    self.journal(tx, record)
                    raise
        self.report('Installed ' + value['id'] + '. Rollback copies retained.')
        return record

    def rollback(self, update_id):
        require(type(update_id) is str and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}', update_id)
                and '..' not in update_id, 'Update ID')
        with self.locked(), directory(self.store / update_id) as tx:
            raw = read_at(tx, 'manifest.json', 128 * 1024)[0]
            signature = read_at(tx, 'manifest.sig', 64)[0]
            value = manifest(raw, signature, self.key)
            require(value['id'] == update_id, 'Transaction identity')
            record = parse(read_at(tx, 'receipt.json', 65536)[0])
            require(record['manifest_sha256'] == sha(raw) and record['id'] == update_id and
                    record['phase'] in ('backing-up', 'preparing-directories', 'installing', 'installed', 'failed-retained', 'rolling-back'),
                    'Transaction cannot be rolled back')
            created = self.validate_created_directories(record, value)
            with contextlib.ExitStack() as stack:
                restore = []
                # Validate ALL current files and ALL backups before changing anything.
                for i, e in enumerate(value['files']):
                    path = self.root / e['path']
                    try:
                        fd = stack.enter_context(directory(path.parent))
                    except FileNotFoundError:
                        fd = None
                    name = path.name
                    current = snapshot(fd, name)[0] if fd is not None else None
                    after = {'sha256': e['sha256'], 'mode': e['mode']}
                    require(current in (e['before'], after), 'Locally changed file; rollback held: ' + e['path'])
                    data = None
                    if e['before'] is not None and current != e['before']:
                        data = read_at(tx, 'backup-' + str(i))[0]
                        require(sha(data) == e['before']['sha256'], 'Corrupt rollback copy')
                    restore.append((e, fd, name, current, data))
                record['phase'] = 'rolling-back'
                self.journal(tx, record)
                for e, fd, name, current, data in reversed(restore):
                    require((snapshot(fd, name)[0] if fd is not None else None) == current, 'File changed during rollback')
                    if current == e['before']:
                        continue
                    self.report('Restoring ' + e['path'])
                    if data is None:
                        os.unlink(name, dir_fd=fd)
                        os.fsync(fd)
                    else:
                        atomic(fd, name, data, e['before']['mode'])
                    require(snapshot(fd, name)[0] == e['before'], 'Restored file verification failed')
                record['retained_directories'] = self.remove_created_directories(created)
                record['phase'] = 'rolled-back'
                self.journal(tx, record)
        self.report('Rolled back ' + update_id + '.')
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'apply'):
        p = sub.add_parser(action)
        p.add_argument('bundle', type=Path)
        if action == 'apply':
            p.add_argument('--accept', required=True, help='approval hash shown by inspect')
    sub.add_parser('rollback').add_argument('update_id')
    sub.add_parser('online-check')
    p = sub.add_parser('online-apply')
    p.add_argument('--accept', required=True)
    sub.add_parser('online-rollback')
    args = parser.parse_args()
    with directory(KEY.parent) as fd:
        key = read_at(fd, KEY.name, 4096)[0]
    if args.action == 'online-check':
        with channel_bundle() as path:
            value, raw, _, _ = bundle(path, key)
            installed = True
            for entry in value['files']:
                target = Path('/') / entry['path']
                try:
                    with directory(target.parent) as fd:
                        actual = snapshot(fd, target.name)[0]
                    installed = installed and actual == {'sha256': entry['sha256'], 'mode': entry['mode']}
                except FileNotFoundError:
                    installed = False
            can_install, message, new_dirs = True, '', []
            if not installed:
                try:
                    plan = Engine('/', STORE, key).preflight(value)
                    fs = os.statvfs('/')
                    needed = 2 * sum(e['bytes'] for e in value['files']) + plan['backup_bytes'] + 64 * 1024**2
                    require(fs.f_bavail * fs.f_frsize >= needed, 'Insufficient free space')
                    new_dirs = plan['directories']
                except (OSError, ValueError) as error:
                    can_install, message = False, str(error)
            print(json.dumps({'id': value['id'], 'title': value['title'], 'notes': value['notes'],
                'restart': value['restart'], 'approval': sha(raw),
                'installed': installed,
                'can_install': can_install, 'preflight_message': message, 'create_directories': new_dirs,
                'bytes': sum(e['bytes'] for e in value['files'])}), flush=True)
        return
    if args.action == 'inspect':
        value, raw, _, _ = bundle(args.bundle, key)
        show(value, raw)
        return
    require('ID=cub' in Path('/etc/os-release').read_text().splitlines() or
            'ID="cub"' in Path('/etc/os-release').read_text().splitlines(), 'Cub OS required')
    if args.action in ('apply', 'rollback', 'online-apply', 'online-rollback'):
        # Never replace Proton while a Windows game may hold its payload open.
        p = subprocess.run(['/usr/bin/pgrep', '-x', 'wineserver'], capture_output=True, timeout=5)
        require(p.returncode == 1, 'Close affected games before updating; Wine status unavailable or active')
        for unit in ('cub-gpu-screening.service', 'cub-cu-trial.service', 'cub-undervolt-trial.service'):
            p = subprocess.run(['/usr/bin/systemctl', 'is-active', unit], capture_output=True, timeout=5)
            require(p.returncode in (3, 4), 'Finish the active hardware test before updating')
    engine = Engine('/', STORE, key)
    if args.action == 'online-apply':
        with channel_bundle() as path:
            engine.apply(path, args.accept)
    elif args.action == 'online-rollback':
        candidates = []
        with directory(STORE) as fd:
            for name in os.listdir(fd):
                if re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}', name) and name != 'worker.lock':
                    with directory(STORE / name) as tx:
                        value = parse(read_at(tx, 'receipt.json', 65536)[0])
                        if value['phase'] in ('backing-up', 'preparing-directories', 'installed', 'installing', 'failed-retained', 'rolling-back'):
                            candidates.append((value['time'], name))
        require(bool(candidates), 'No retained component update to roll back')
        engine.rollback(max(candidates)[1])
    elif args.action == 'apply':
        value, raw, _, _ = bundle(args.bundle, key)
        show(value, raw)
        engine.apply(args.bundle, args.accept)
    else:
        engine.rollback(args.update_id)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit('Update stopped: ' + str(error))
