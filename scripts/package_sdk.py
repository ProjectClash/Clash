#!/usr/bin/env python3
"""Package a built SDK with its pinned sources and license notices."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import tomllib
import urllib.request
import zipfile

SDK_CONTENTS = ['Clash.xcframework', 'LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md',
                'THIRD_PARTY_LICENSES', 'SOURCES.json']
EASYTIER = 'github.com/easytier/easytier/easytier-go'


def sha(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def module_directory(name):
    return name.replace('/', '__').replace('\\', '__').replace(':', '_').replace('@', '_')


def verify_inventory(root):
    record = json.loads((root / 'INDEX.json').read_text())
    if record.get('schema') != 1 or not record.get('modules'):
        raise ValueError('Missing linked-module license inventory')
    for module in record['modules']:
        for item in module['files']:
            path = root / module_directory(module['module']) / item['name']
            if not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or sha(path) != item['sha256']:
                raise ValueError('Missing or changed module license')
    return record


def wasm_provenance(root):
    text = (root / 'provenance.go').read_text()
    commit = re.search(r'Commit\s*=\s*"([a-f0-9]{40})"', text)
    digest = re.search(r'SHA256\s*=\s*"([a-f0-9]{64})"', text)
    if not commit or not digest or sha(root / 'easytier_core.wasm') != digest[1]:
        raise ValueError('EasyTier embedded WASM differs from its source provenance')
    return dict(commit=commit[1], wasmSHA256=digest[1])


def fetch(url, destination, digest=None):
    if not destination.exists():
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=90) as response, destination.open('wb') as file:
                    shutil.copyfileobj(response, file)
                break
            except OSError:
                destination.unlink(missing_ok=True)
                if attempt == 2: raise
                time.sleep(attempt + 1)
    if digest and sha(destination) != digest:
        raise ValueError('Dependency source checksum mismatch: ' + destination.name)


def package_rust_sources(source_archive, output, notices):
    """Preserve all Cargo.lock sources; this is a conservative target superset."""
    with tarfile.open(source_archive) as archive:
        prefix = archive.getnames()[0] + '/'
        lock = tomllib.loads(archive.extractfile(prefix + 'Cargo.lock').read().decode())
    downloads = output / 'rust-source-archives'
    downloads.mkdir()
    rust_notices = notices / 'EasyTier-Cargo'
    rust_notices.mkdir()
    requests = {}
    for item in lock['package']:
        source = item.get('source', '')
        if not source: continue  # Workspace sources are in the main source archive.
        if source == 'registry+https://github.com/rust-lang/crates.io-index':
            name, version = item['name'], item['version']
            if not re.fullmatch(r'[A-Za-z0-9_.+-]+', name + version):
                raise ValueError('Invalid Cargo package identity')
            filename = name + '-' + version + '.crate'
            url = 'https://static.crates.io/crates/' + name + '/' + filename
            digest = item['checksum']
        elif source.startswith('git+'):
            match = re.fullmatch(r'git\+https://github.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:\?[^#]+)?#([a-f0-9]{40})', source)
            if not match: raise ValueError('Unsupported pinned Cargo Git source')
            owner, repo, commit = match.groups()
            filename = owner + '-' + repo + '-' + commit + '.tar.gz'
            url = 'https://codeload.github.com/' + owner + '/' + repo + '/tar.gz/' + commit
            digest = None
        else:
            raise ValueError('Unsupported Cargo source: ' + source)
        requests[filename] = dict(url=url, sha256=digest)

    def collect(entry):
        name, source = entry
        target = downloads / name
        fetch(source['url'], target, source['sha256'])
        saved = []
        with tarfile.open(target) as archive:
            for member in archive:
                path = Path(member.name)
                if not member.isfile() or path.is_absolute() or '..' in path.parts:
                    continue
                upper = path.name.upper()
                if upper.startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE')):
                    # Unique path beneath the original archive, no path rewriting.
                    dest = rust_notices / name / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(archive.extractfile(member).read())
                    saved.append(dict(path=dest.relative_to(notices).as_posix(), sha256=sha(dest)))
        return dict(archive=name, sourceURL=source['url'], sha256=sha(target), notices=saved)

    with ThreadPoolExecutor(max_workers=8) as workers:
        records = sorted(workers.map(collect, sorted(requests.items())), key=lambda item: item['archive'])
    index = dict(schema=1, scope='All Cargo.lock dependencies, including non-WASM targets and build dependencies; not a claim that all are linked.',
                 packages=lock['package'], sources=records)
    (rust_notices / 'INDEX.json').write_text(json.dumps(index, indent=2) + '\n')
    make_zip(output / 'EasyTier-dependencies.zip', output, ['rust-source-archives'])
    # Full original archives retain any notices embedded in source files, too.
    return dict(archive='EasyTier-dependencies.zip', sha256=sha(output / 'EasyTier-dependencies.zip'),
                inventory='THIRD_PARTY_LICENSES/EasyTier-Cargo/INDEX.json', sources=len(records))


def make_zip(output, root, names):
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in names:
            path = root / name
            if path.is_symlink():
                raise ValueError('Unexpected symlink in SDK package root')
            if not path.exists():
                raise ValueError('Missing SDK package member: ' + name)
            files = sorted(path.rglob('*')) if path.is_dir() else [path]
            for file in files:
                relative = file.relative_to(root).as_posix()
                if file.is_symlink():
                    # macOS frameworks contain version aliases. Keep the links,
                    # but never read a target outside this package.
                    if not file.resolve().is_relative_to(path.resolve()):
                        raise ValueError('External symlink in SDK package')
                    info = zipfile.ZipInfo(relative)
                    info.create_system = 3
                    info.external_attr = 0o120777 << 16
                    archive.writestr(info, str(file.readlink()))
                elif file.is_file():
                    archive.write(file, relative)


def download_module(name):
    result = subprocess.check_output(['go', 'mod', 'download', '-json', name], text=True)
    value = json.loads(result)
    if value.get('Error'):
        raise ValueError('Module source unavailable: ' + name)
    return Path(value['Dir'])


def verify_framework(root, commit):
    slices = {'ios-arm64', 'ios-arm64_x86_64-simulator', 'macos-arm64_x86_64',
              'tvos-arm64', 'tvos-arm64_x86_64-simulator'}
    records = []
    for name in sorted(slices):
        path = root / 'Clash.xcframework' / name / 'Clash.framework/Resources/ClashBuildInfo.json'
        info = json.loads(path.read_text())
        if (info.get('sourceRevision') != commit or info.get('sourceDirty') is not False
                or info.get('debugBuild') is not False or info.get('internalDiagnostics') is not False):
            raise ValueError('SDK build provenance does not match this clean release source')
        records.append(info)
    if any(info != records[0] for info in records):
        raise ValueError('SDK slices have different build provenance')
    return records[0]


def prepare(root, inventory, output):
    remote = subprocess.check_output(['git', 'remote', 'get-url', 'origin'], cwd=root, text=True).strip()
    if remote not in {'https://github.com/ProjectClash/Clash', 'https://github.com/ProjectClash/Clash.git',
                      'git@github.com:ProjectClash/Clash.git', 'git@github:ProjectClash/Clash.git'}:
        raise ValueError('SDK packaging requires the independent public repository')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    build_info = verify_framework(root, commit)
    record = verify_inventory(inventory)
    output.mkdir(parents=True, exist_ok=False)
    notices = output / 'THIRD_PARTY_LICENSES'
    shutil.copytree(inventory, notices)
    modules = {item['module']: item for item in record['modules']}
    easy = modules[EASYTIER]
    easy_root = download_module(EASYTIER + '@' + easy['version'])
    provenance = wasm_provenance(easy_root / 'internal/artifact')
    source_url = 'https://codeload.github.com/EasyTier/EasyTier/tar.gz/' + provenance['commit']
    source_name = 'EasyTier-source-' + provenance['commit'] + '.tar.gz'
    with urllib.request.urlopen(source_url, timeout=120) as response, (output / source_name).open('xb') as file:
        shutil.copyfileobj(response, file)
    # Inspect the archive without extracting untrusted paths.
    with tarfile.open(output / source_name) as source:
        prefix = 'EasyTier-' + provenance['commit'] + '/'
        names = set(source.getnames())
        for required in ['Cargo.lock', 'Cargo.toml', 'LICENSE', 'script/build-wasi-core.sh']:
            if prefix + required not in names:
                raise ValueError('Incomplete EasyTier corresponding source: ' + required)
        license_file = source.extractfile(prefix + 'LICENSE')
        (notices / module_directory(EASYTIER) / 'EMBEDDED-CORE-LICENSE').write_bytes(license_file.read())
    provenance.update(sourceURL=source_url, sourceArchive=source_name,
                      sourceArchiveSHA256=sha(output / source_name),
                      buildScript='script/build-wasi-core.sh')
    provenance['dependencies'] = package_rust_sources(output / source_name, output, notices)
    (notices / module_directory(EASYTIER) / 'EMBEDDED-CORE.json').write_text(json.dumps(provenance, indent=2) + '\n')
    lzo = modules['github.com/rasky/go-lzo']
    lzo_root = download_module(lzo['module'] + '@' + lzo['version'])
    shutil.copyfile(lzo_root / 'README.md', notices / module_directory(lzo['module']) / 'UPSTREAM-README.md')
    shutil.copyfile(root / 'scripts/ORIGINAL-LZO-NOTICE.txt', notices / module_directory(lzo['module']) / 'ORIGINAL-LZO-NOTICE.txt')
    gomobile = download_module('github.com/sagernet/gomobile@v0.1.13')
    runtime = notices / 'gomobile-runtime'
    runtime.mkdir()
    shutil.copyfile(gomobile / 'LICENSE', runtime / 'LICENSE')
    goroot = Path(subprocess.check_output(['go', 'env', 'GOROOT'], cwd=root / 'bind/clash', text=True).strip())
    shutil.copyfile(goroot / 'LICENSE', notices / 'GO-RUNTIME-LICENSE')
    sources = dict(schema=1, kernel=dict(commit=commit, url='https://github.com/ProjectClash/Clash/tree/' + commit),
                   easyTier=provenance, gomobile=dict(version='v0.1.13', url='https://github.com/sagernet/gomobile/tree/v0.1.13'),
                   goToolchain=build_info['goToolchain'],
                   linkedGoModules=record['modules'])
    (output / 'SOURCES.json').write_text(json.dumps(sources, indent=2) + '\n')
    for name in ['LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md']:
        shutil.copyfile(root / name, output / name)
    # The framework can be large; archive it in place without a duplicate copy.
    make_zip(output / 'Clash.xcframework.zip', root, ['Clash.xcframework'])
    with zipfile.ZipFile(output / 'Clash.xcframework.zip', 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in SDK_CONTENTS[1:]:
            path = output / name
            for file in sorted(path.rglob('*')) if path.is_dir() else [path]:
                if file.is_file(): archive.write(file, file.relative_to(output).as_posix())
    make_zip(output / 'THIRD_PARTY_LICENSES.zip', output, SDK_CONTENTS[1:])
    assets = ['Clash.xcframework.zip', 'THIRD_PARTY_LICENSES.zip', 'EasyTier-dependencies.zip', source_name, 'SOURCES.json']
    (output / 'SHA256SUMS').write_text(''.join(sha(output / name) + '  ' + name + '\n' for name in assets))
    print('Packaged SDK, licenses, exact embedded source and SHA256SUMS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(Path.cwd(), args.inventory.resolve(), args.output.resolve())
