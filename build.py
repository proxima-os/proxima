#!/usr/bin/env python3
from __future__ import annotations
import abc
import argparse
import asyncio
from collections import OrderedDict
from concurrent import futures
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request


ARCHES = ['x86_64']
BUF_SIZE = 0x10000
TOOLCHAIN_PACKAGES = ['host-binutils', 'host-gcc', 'hydrogen']
ISO_PACKAGES = ['host-limine']

BUILDDIR = Path('build')
SCRIPTDIR = Path(__file__).resolve().parent
SOURCEDIR = BUILDDIR / 'sources'
PACKAGEDIR = SCRIPTDIR / 'packages'
VALID_ID = re.compile(r'^[a-zA-Z0-9-_]+$')


arch: str = None
arch_build_dir: Path = None
target: str = None
threads: int = 1
executor: futures.ThreadPoolExecutor = None
cross_file: Path = None
build_env = os.environ.copy()


build_env['sroot'] = SCRIPTDIR.absolute()


def hash_file(path) -> str:
    sha256 = hashlib.sha256()

    with path.open('rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


class SourceRef:
    def __init__(self, pkg: str, id: str):
        self.pkg = pkg
        self.id = id

    def resolve(self) -> Source:
        return get_package(self.pkg).sources[self.id]

    @staticmethod
    def parse(pkg: Package, text: str) -> SourceRef:
        parts = text.split(':')
        if len(parts) > 2:
            raise RuntimeError(f'invalid source reference "${text}"')
        elif len(parts) == 2:
            return SourceRef(parts[0], parts[1])
        else:
            return SourceRef(pkg.id, parts[0])


class Source(abc.ABC):
    def __init__(self, id: str, dir: Path):
        self.id = id
        self.dir = dir
        self.marker = dir / f'{id}.marker'
        self.out = dir / id
        self.future: futures.Future = None
        self.referenced = False

    def resolve(self):
        pass

    def get(self):
        if not self.marker.exists():
            self.dir.mkdir(parents=True, exist_ok=True)
            self.run()
            self.marker.touch()

    def reference(self):
        if not self.referenced:
            self.referenced = True
            self.do_reference()
            self.future = executor.submit(self.get)

    def do_reference(self):
        pass

    @abc.abstractmethod
    def run(self):
        pass

    @staticmethod
    @abc.abstractmethod
    def parse(pkg: Package, id: str, dir: Path, data: dict) -> Source:
        pass


class DownloadSource(Source):
    def __init__(self, id: str, dir: Path, url: str, sha256: str):
        super().__init__(id, dir)
        self.url = url
        self.sha256 = sha256

    def run(self):
        print(f'Downloading {self.url} to {self.out}...')
        urllib.request.urlretrieve(self.url, self.out)
        if hash_file(self.out) != self.sha256:
            raise RuntimeError('checksum mismatch for {self.out}')

    @staticmethod
    def parse(_, id, dir, data) -> Source:
        return DownloadSource(id, dir, data['url'], data['sha256'])


class TarSource(Source):
    def __init__(self, id: str, dir: Path, input: SourceRef, compression: str, strip: int, patches: list[Path]):
        super().__init__(id, dir)
        self.input = input
        self.compression = compression
        self.strip = strip
        self.patches = patches

    def resolve(self):
        self.input = self.input.resolve()

    def do_reference(self):
        self.input.reference()

    def run(self):
        self.input.future.result()

        print(f'Extracting {self.input.out} to {self.out}')

        with tarfile.open(self.input.out, mode=f'r:{self.compression}') as tar:
            tar.extractall(self.out, filter=self.extract_filter)

        for patch in self.patches:
            print(f'Applying {patch}')
            subprocess.run(['patch', '-sp1', '-i', patch.absolute()], check=True, cwd=self.out)

    def extract_filter(self, member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
        member = tarfile.tar_filter(member, path)

        parts = member.path.split('/')
        if len(parts) <= self.strip:
            return None

        member.path = '/'.join(parts[self.strip:])
        return member

    @staticmethod
    def parse(pkg, id, dir, data) -> Source:
        patches = []

        for patch in data.get('patches', []):
            patches.append(pkg.pkg_dir / patch)

        return TarSource(id, dir, SourceRef.parse(pkg, data['input']), data.get('compression', ''), data.get('strip', 0), patches)


SOURCE_TYPES: dict[str, Source] = {
    'download': DownloadSource,
    'tar': TarSource,
}


class Package:
    def __init__(self, id: str, version: str, pkg_dir: Path):
        self.id = id
        self.version = version
        self.sources: dict[str, Source] = {}
        self.steps: dict[str, Step] = {}
        self.referenced = False
        self.pkg_dir = pkg_dir
        self.src_dir = SOURCEDIR / id / version
        self.build_dir = arch_build_dir / id / version

    @staticmethod
    def load(id: str):
        if not VALID_ID.match(id):
            raise RuntimeError(f'invalid package id: "{id}"')
        dir = PACKAGEDIR / id

        with (dir / 'pkg.json').open('r') as f:
            data: dict = json.load(f, object_pairs_hook=OrderedDict)

        pkg = Package(id, data['version'], dir)

        sources = data.get('sources', {})

        for src in sources:
            if not VALID_ID.match(src):
                raise RuntimeError(f'invalid source id: "{src}"')

            srcdata = sources[src]
            pkg.sources[src] = SOURCE_TYPES[srcdata['type']].parse(pkg, src, pkg.src_dir, srcdata)

        steps = data.get('steps', {})
        last_step = None

        for step in steps:
            if not VALID_ID.match(step):
                raise RuntimeError(f'invalid step id: "{step}"')

            stepdata = steps[step]
            s = Step.parse(pkg, step, stepdata)

            if last_step:
                s.dependencies.append(StepRef(id, last_step))

            pkg.steps[step] = s
            last_step = step

        return pkg

    def resolve(self):
        for src in self.sources:
            self.sources[src].resolve()

        for step in self.steps:
            self.steps[step].resolve()


class StepRef:
    def __init__(self, pkg: str, id: str):
        self.pkg = pkg
        self.id = id

    @staticmethod
    def parse(pkg: str, text: str) -> StepRef:
        parts = text.split(':')
        if len(parts) > 2:
            raise RuntimeError(f'invalid step reference "{text}"')
        elif len(parts) == 1:
            return StepRef(pkg, parts[0])
        else:
            return StepRef(parts[0], parts[1])

    def resolve(self) -> Step:
        return get_package(self.pkg).steps[self.id]


class Step:
    def __init__(self, pkg: Package, id: str):
        self.pkg = pkg
        self.id = id
        self.dependencies: list[Step] = []
        self.started = False
        self.done = False
        self.referenced = False
        self.marker = pkg.build_dir / f'{id}.marker'

    async def run(self):
        if not self.done:
            if self.started:
                raise RuntimeError(f'circular dependency')
            self.started = True

            for dep in self.dependencies:
                await dep.run()

            if self.marker.exists():
                self.done = True
                return

            for src in self.pkg.sources:
                self.pkg.sources[src].future.result()

            print(f'Running {self.pkg.id}:{self.id}')
            context = SCRIPTDIR / 'support' / 'context.sh'
            script = self.pkg.pkg_dir / (self.id + '.sh')

            cwd = self.pkg.build_dir / 'build'
            cwd.mkdir(parents=True, exist_ok=True)

            env = build_env.copy()

            env['pkgdir'] = self.pkg.pkg_dir.absolute()
            env['build'] = cwd.absolute()

            for src in self.pkg.sources:
                env[f'src_{src}'] = self.pkg.sources[src].out.absolute()

            subprocess.run(
                [context, script.absolute()],
                check=True,
                cwd=cwd,
                env=env
            )

            self.marker.touch()
            self.done = True

    @staticmethod
    def parse(pkg: Package, id: str, data: dict):
        step = Step(pkg, id)

        for dep in data.get('depends', []):
            step.dependencies.append(StepRef.parse(pkg, dep))

        return step

    def resolve(self):
        for i in range(len(self.dependencies)):
            self.dependencies[i] = self.dependencies[i].resolve()

    def reference(self):
        if not self.referenced:
            self.referenced = False

            for src in self.pkg.sources:
                self.pkg.sources[src].reference()

            for dep in self.dependencies:
                dep.reference()


loaded_packages: dict[str, Package] = {}


def get_package(id: str) -> Package:
    if not id in loaded_packages:
        pkg = Package.load(id)
        loaded_packages[id] = pkg
        pkg.resolve()

    return loaded_packages[id]


def clean(args):
    if args.all:
        for arch in ARCHES:
            dir = BUILDDIR / arch
            if dir.exists():
                shutil.rmtree(dir)
    else:
        dir = BUILDDIR / args.target
        if dir.exists():
            shutil.rmtree(dir)

    if args.sources:
        if SOURCEDIR.exists():
            shutil.rmtree(SOURCEDIR)


def setup_packages(ids: list[str]):
    for id in ids:
        pkg = get_package(id)
        for step in pkg.steps:
            pkg.steps[step].reference()


async def build_packages(ids: list[str]):
    try:
        for id in ids:
            pkg = get_package(id)
            for step in pkg.steps:
                await pkg.steps[step].run()
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def build_toolchain():
    global cross_file

    tools_dir = (arch_build_dir / 'tools').absolute()
    bin_dir = tools_dir / 'bin'
    cross_file = arch_build_dir / 'meson-cross.txt'

    with cross_file.open('w') as f:
        f.write(f'''
                [binaries]
                ar='{bin_dir}/{target}-ar'
                c='{bin_dir}/{target}-gcc'
                cpp='{bin_dir}/{target}-g++'
                objcopy='{bin_dir}/{target}-objcopy'
                strip='{bin_dir}/{target}-strip'

                [host_machine]
                system = 'proxima'
                cpu_family = 'x86'
                cpu = 'x86_64'
                endian = 'little'

                [properties]
                sys_root='{(arch_build_dir / 'sysroot').absolute()}'
                pkg_config_libdir = '{(arch_build_dir / 'sysroot' / 'usr' / 'lib' / 'pkgconfig').absolute()}'
                ''')

    build_env['meson_cross'] = cross_file.absolute()

    asyncio.run(build_packages(TOOLCHAIN_PACKAGES))


def build(args):
    setup_packages(TOOLCHAIN_PACKAGES + args.packages)
    build_toolchain()
    asyncio.run(build_packages(args.packages))


def setup(_):
    setup_packages(TOOLCHAIN_PACKAGES)
    build_toolchain()


def create_iso(packages, out):
    setup_packages(TOOLCHAIN_PACKAGES + ISO_PACKAGES + packages)
    build_toolchain()
    asyncio.run(build_packages(ISO_PACKAGES + packages))

    subprocess.run([
        SCRIPTDIR / 'support' / 'mkiso.sh',
        arch_build_dir / 'sysroot',
        arch_build_dir / 'tools',
        out], check=True)


def iso(args):
    out = args.output
    if not out:
        out = arch_build_dir / 'proxima.iso'

    create_iso(args.packages, out)
    print(f'Created Proxima ISO at {out}')


def main():
    global arch, arch_build_dir, target, threads, executor

    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help='set the target architecture', default='x86_64', choices=ARCHES)
    parser.add_argument('-j', help='set the number of threads', type=int, default=multiprocessing.cpu_count(), dest='threads')

    subparsers = parser.add_subparsers(required=True, title='commands')

    clean_parser = subparsers.add_parser('clean', help='remove the build tree')
    clean_parser.add_argument('-a', '--all', help='remove the build trees for all architectures', action='store_true')
    clean_parser.add_argument('-s', '--sources', help='remove sources as well', action='store_true')
    clean_parser.set_defaults(func=clean)

    build_parser = subparsers.add_parser('build', help='build and install packages')
    build_parser.add_argument('packages', help='the packages to build and install', nargs='+', metavar='PACKAGE')
    build_parser.set_defaults(func=build)

    setup_parser = subparsers.add_parser('setup', help='set up the toolchain for development')
    setup_parser.set_defaults(func=setup)

    iso_parser = subparsers.add_parser('iso', help='create a bootable ISO image')
    iso_parser.add_argument('-o', '--output', help='the location to write the ISO to')
    iso_parser.add_argument('packages', help='the packages to build and install', nargs='*', metavar='PACKAGE')
    iso_parser.set_defaults(func=iso)

    args = parser.parse_args()

    arch = args.target
    arch_build_dir = BUILDDIR / args.target
    target = f'{arch}-unknown-proxima'
    threads = args.threads
    executor = futures.ThreadPoolExecutor(max_workers=threads)

    build_env['target'] = target
    build_env['broot'] = arch_build_dir.absolute()
    build_env['threads'] = str(threads)

    args.func(args)


if __name__ == '__main__':
    main()
