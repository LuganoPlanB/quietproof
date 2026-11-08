#!/usr/bin/env python3
"""Sign exact UTF-8 bytes with bundled Sparrow/Drongo in disposable test wallets.

Requires an explicit Sparrow application image, JDK25+, private cache, and marked
disposable wallet directory. No downloads, default wallets, network calls or RPC.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

MARKER = '.quietproof-disposable.json'
LIMIT = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_directory(path, *, create=False):
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, 'directory must be owned and mode 0700')


def read_file(path, *, private=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= LIMIT, 'bounded regular file required')
        if private:
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
                    'private input must be owned and mode 0600')
        data = stream.read(LIMIT + 1)
        require(len(data) <= LIMIT, 'input too large')
        return data


def write_private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(data)


def run(command, *, cwd=None):
    # Never forward library output on failures (it could contain wallet data).
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=120)
    require(result.returncode == 0, 'bundled Sparrow operation failed; no output disclosed')
    return result.stdout


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(args):
    installation = args.sparrow.resolve(strict=True)
    runtime = installation / 'lib/runtime'
    image = runtime / 'lib/modules'
    library = runtime / 'lib/libsecp256k1.so'
    source = Path(__file__).with_name('SparrowSigner.java')
    identity = {'modulesSha256': digest(image), 'secp256k1Sha256': digest(library),
                'adapterSha256': digest(source), 'release': (runtime / 'release').read_text().splitlines()[0],
                'sparrowVersion': '2.5.6',
                'drongoSourceCommit': '13059ebc2979640b30bc1534b4584e2191578672'}
    config = (installation / 'lib/app/Sparrow.cfg').read_text()
    require('-Djpackage.app-version=2.5.6' in config, 'only inspected Sparrow 2.5.6 is supported')
    java = args.jdk.resolve(strict=True) / 'bin'
    for name in ['java', 'javac', 'jimage']:
        require((java / name).is_file(), 'JDK java, javac and jimage required')
    native_override = java.parent / 'lib/libsecp256k1.so'
    require(not native_override.exists() or digest(native_override) == identity['secp256k1Sha256'],
            'JDK native secp256k1 override differs from supplied Sparrow')
    # Bind cache to the exact installed bytes, source and JDK version.
    identity['jdkReleaseSha256'] = digest(java.parent / 'release')
    identity['jdkJavaSha256'] = digest(java / 'java')
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    private_directory(args.cache, create=True)
    build = args.cache / key
    if not build.exists():
        with tempfile.TemporaryDirectory(prefix='prepare-', dir=args.cache) as temporary:
            stage = Path(temporary)
            run([str(java / 'jimage'), 'extract', '--dir', str(stage / 'modules'), str(image)])
            resources = stage / 'resources/native/linux/x64'
            resources.mkdir(parents=True)
            shutil.copyfile(library, resources / library.name)
            modules = sorted(p for p in (stage / 'modules').iterdir()
                             if not p.name.startswith(('java.', 'jdk.')))
            classpath = os.pathsep.join(map(str, modules + [stage / 'resources']))
            run([str(java / 'javac'), '-cp', classpath, '-d', str(stage / 'classes'), str(source)])
            stage.rename(build)
    modules = sorted(p for p in (build / 'modules').iterdir()
                     if not p.name.startswith(('java.', 'jdk.')))
    classpath = os.pathsep.join(map(str, modules + [build / 'resources', build / 'classes']))
    return java, classpath, identity


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['create', 'address', 'sign', 'verify', 'provenance'])
    parser.add_argument('--sparrow', type=Path, required=True, help='installed application image')
    parser.add_argument('--jdk', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--network', choices=['signet', 'testnet4', 'regtest'], required=True)
    parser.add_argument('--wallet-dir', type=Path)
    parser.add_argument('--script-kind', choices=['p2wpkh', 'p2pkh', 'p2tr'], default='p2wpkh')
    parser.add_argument('--key-path', choices=['m/0/0', 'm/1/0'], default='m/0/0',
                        help='explicit owned receive or change key; receive m/0/0 is the default')
    parser.add_argument('--format', choices=['bip322-simple', 'bip322-full', 'standard', 'electrum', 'bip137'],
                        default='bip322-simple')
    parser.add_argument('--address')
    parser.add_argument('--message', type=Path, help='UTF-8 file; every byte including final newline is signed')
    parser.add_argument('--signature', type=Path, help='private signature JSON for verification')
    parser.add_argument('--output', type=Path, help='new private signature JSON file')
    args = parser.parse_args(argv)
    args.cache = args.cache.absolute()
    os.umask(0o077)
    try:
        require(args.action != 'create' or args.key_path == 'm/0/0',
                'wallet creation requires default receive key path')
        if args.action in ['sign', 'verify']:
            require(args.message and args.address, '--message and --address required')
            data = read_file(args.message)
            data.decode('utf-8', errors='strict')
            if args.action == 'sign':
                require(args.output and not args.output.exists(), 'new --output required')
            else:
                require(args.signature, '--signature required')
                signature = read_file(args.signature, private=True)
                json.loads(signature)
        if args.action != 'provenance':
            require(args.wallet_dir, '--wallet-dir required')
            if args.action == 'create':
                args.wallet_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
                write_private(args.wallet_dir / MARKER,
                              json.dumps({'network': args.network, 'disposable': True}).encode())
            private_directory(args.wallet_dir)
            marker = json.loads(read_file(args.wallet_dir / MARKER, private=True))
            require(marker == {'network': args.network, 'disposable': True}, 'disposable network marker mismatch')
            if args.action != 'create':
                read_file(args.wallet_dir / (args.script_kind.upper() + '.mv.db'), private=True)
        java, classpath, identity = prepare(args)
        if args.action == 'provenance':
            print(json.dumps(identity, sort_keys=True))
            return 0
        with tempfile.TemporaryDirectory(prefix='operation-', dir=args.cache) as temporary:
            directory = Path(temporary)
            operation_wallet = args.wallet_dir.resolve()
            if args.action != 'create':
                # Stock Storage may write its database during open/close. Keep
                # the supplied marked wallet byte-for-byte unchanged.
                operation_wallet = directory / 'wallet'
                operation_wallet.mkdir(mode=0o700)
                wallet_name = args.script_kind.upper() + '.mv.db'
                write_private(operation_wallet / wallet_name,
                              read_file(args.wallet_dir / wallet_name, private=True))
            command = [str(java / 'java'), '--enable-native-access=ALL-UNNAMED',
                       '-Duser.home=' + str(directory), '-cp', classpath, 'SparrowSigner',
                       args.action, args.network, str(operation_wallet), args.script_kind, args.key_path]
            if args.action in ['sign', 'verify']:
                message = directory / 'message'
                write_private(message, data)
                command += [args.address, args.format, str(message)]
                if args.action == 'verify':
                    receipt = directory / 'signature.json'
                    write_private(receipt, signature)
                    command.append(str(receipt))
            result = json.loads(run(command, cwd=directory))
        if args.action == 'sign':
            result['messageSha256'] = hashlib.sha256(data).hexdigest()
            result['provenance'] = identity
            write_private(args.output, (json.dumps(result, sort_keys=True) + '\n').encode())
            del result['signature']
            result['output'] = str(args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Sparrow helper rejected input or operation; wallet and signature data withheld', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
