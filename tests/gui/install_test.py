"""Opt-in Linux installed-package contract; source files are qualification inputs only.

The exec wrapper only tightens this owned child's policy. libseccomp is a test
prerequisite, never a GUI runtime dependency. API: libseccomp seccomp_rule_add(3)
and seccomp_load(3), https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html.
"""
import argparse
import configparser
import ctypes
import ctypes.util
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def now():
    return datetime.now(timezone.utc).isoformat()


def deny_network():
    library = ctypes.util.find_library('seccomp')
    if not library:
        raise RuntimeError('offline qualification requires existing libseccomp')
    seccomp = ctypes.CDLL(library)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('cannot create owned offline filter')
    try:
        for name in (b'socket', b'socketpair', b'connect'):
            number = seccomp.seccomp_syscall_resolve_name(name)
            if number < 0 or seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0):
                raise RuntimeError('cannot add owned offline rule')
        if seccomp.seccomp_load(context):
            raise RuntimeError('cannot load owned offline filter')
    finally:
        seccomp.seccomp_release(context)
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            with socket.socket(family, socket.SOCK_STREAM):
                pass
        except OSError as error:
            assert error.errno == errno.EPERM, 'offline guard returned unexpected denial'
        else:
            raise AssertionError('offline socket guard ineffective')
    print('OFFLINE guard: IPv4/IPv6/Unix socket creation denied EPERM; inherited across exec', flush=True)


def tree_contract(prefix, source):
    gui = prefix/'bin/quietproof-prover-gui'
    assert gui.is_file() and os.access(gui, os.X_OK)
    expected = {
        'share/quietproof/fonts/Inter.ttf': 'src/gui/assets/Inter.ttf',
        'share/quietproof/fonts/Inter-OFL.txt': 'src/gui/assets/Inter-OFL.txt',
        'share/icons/hicolor/scalable/apps/quietproof-prover.svg': 'docs/public/quietproof-mark.svg',
        'share/applications/quietproof-prover.desktop': 'src/gui/assets/quietproof-prover.desktop',
        'share/doc/LongfellowZKQuietProof/docs/guide/native-gui.md': 'docs/guide/native-gui.md',
        'share/doc/quietproof-prover-gui/DEPENDENCIES.md': 'src/gui/assets/DEPENDENCIES.md',
        'share/doc/quietproof-prover-gui/COPYING': 'COPYING',
        'share/doc/quietproof-prover-gui/Plan-B-theme-permission.txt': 'LICENSES/Plan-B-theme-permission.txt',
        'share/doc/quietproof-prover-gui/LICENSE': 'src/gui/vendor/LICENSE',
        'share/doc/quietproof-prover-gui/SDL-LICENSE.txt': 'src/gui/vendor/SDL-LICENSE.txt',
        'share/doc/quietproof-prover-gui/curl-COPYING.txt': 'src/gui/assets/curl-COPYING.txt',
    }
    for installed, original in expected.items():
        assert (prefix/installed).read_bytes() == (source/original).read_bytes(), installed+' identity changed'
    assert not (prefix/'bin/quietproof-gui-assets').exists(), 'development font directory installed'
    generated = [str(p.relative_to(prefix)) for p in prefix.rglob('*')
                 if p.is_file() and any(x in ('dist', 'cache', 'node_modules') for x in p.relative_to(prefix).parts)]
    assert not generated, f'generated development artifacts installed: {len(generated)}; first={generated[:1]}'
    entry = configparser.ConfigParser(interpolation=None)
    entry.read(prefix/'share/applications/quietproof-prover.desktop')
    assert entry['Desktop Entry']['Exec'] == 'quietproof-prover-gui'
    assert entry['Desktop Entry']['Icon'] == 'quietproof-prover'
    assert entry['Desktop Entry']['Terminal'] == 'false'
    return len(expected)


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '--deny-network':
        deny_network()
        os.execv(sys.argv[2], sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('prefix', 'source', 'evidence'):
        parser.add_argument('--'+option, type=Path, required=True)
    parser.add_argument('--request', type=Path)
    parser.add_argument('--proof', type=Path)
    parser.add_argument('--tree-only', action='store_true')
    args = parser.parse_args()
    prefix, source, evidence = (x.resolve() for x in (args.prefix, args.source, args.evidence))
    evidence.mkdir(parents=True, exist_ok=False)
    result = {'startedAt': now(), 'checks': [], 'screenshots': [], 'ownedProcesses': [], 'status': 'running'}
    try:
        result['assetContracts'] = tree_contract(prefix, source)
        if args.tree_only:
            result.update(status='passed', executed=1, passed=1, failed=0, skipped=0)
            return
        assert args.request and args.proof
        request, proof = args.request.resolve(), args.proof.resolve()
        with tempfile.TemporaryDirectory(prefix='quietproof-installed-offline-') as temporary:
            root = Path(temporary); root.chmod(0o700)
            environment = dict(os.environ, HOME=str(root/'home'), XDG_DATA_HOME=str(root/'data'),
                XDG_CONFIG_HOME=str(root/'config'), XDG_CACHE_HOME=str(root/'cache'),
                SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software')
            for key in ('DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','LD_LIBRARY_PATH'):
                environment.pop(key, None)
            (root/'home').mkdir()
            # The desktop entry has no request placeholder: ordinary launcher
            # activation must also work before a file is selected.
            command = [sys.executable,str(Path(__file__).resolve()),'--deny-network',
                str(prefix/'bin/quietproof-prover-gui'),'--smoke-test']
            started=now()
            value=subprocess.run(command,cwd=root,env=environment,capture_output=True,text=True,timeout=30,close_fds=True)
            log=evidence/'launcher.log';log.write_text(value.stdout+value.stderr)
            result['checks'].append({'name':'offline-desktop-launch','command':command,'cwd':str(root),
                'startedAt':started,'completedAt':now(),'exit':value.returncode,'log':str(log)})
            assert value.returncode==0 and 'GUI request: loaded=0 error=0' in value.stdout
            assert f'GUI assets: font={prefix}/share/quietproof/fonts/Inter.ttf renderer=software' in value.stdout
            destination = root/'saved.qpf'; replaced = root/'existing.qpf'
            replaced.write_bytes(b'old public output')
            for index,(theme,font,pixel,size) in enumerate((('light','1',1,(400,640)),('dark','1.5',2,(400,640)))):
                events = ['proof-fixture '+str(proof),'await-proof','tab','backtab','pagedown','pageup',
                    'capture '+str(evidence/f'{theme}-result.bmp'),
                    'control 11','destination '+str(root/'absent/failure.qpf'),'control 307','await-save',
                    'capture '+str(evidence/f'{theme}-failure.bmp'), 'destination '+str(destination),
                    'control 307','await-save','capture '+str(evidence/f'{theme}-saved.bmp'),
                    'control 11','destination '+str(replaced),'control 307','await-save',
                    'capture '+str(evidence/f'{theme}-approval.bmp'),'control 307','await-save',
                    'capture '+str(evidence/f'{theme}-replaced.bmp')]
                # The second scenario gets independent destination state.
                destination.unlink(missing_ok=True); replaced.write_bytes(b'old public output')
                script = evidence/(theme+'.events'); script.write_text('\n'.join(events)+'\n')
                command = [sys.executable,str(Path(__file__).resolve()),'--deny-network',str(prefix/'bin/quietproof-prover-gui'),
                    '--smoke-test','--request',str(request),'--theme',theme,'--font-scale',font,
                    '--pixel-scale',str(pixel),'--width',str(size[0]),'--height',str(size[1]),'--test-events',str(script)]
                started=now()
                value=subprocess.run(command,cwd=root,env=environment,capture_output=True,text=True,timeout=240,close_fds=True)
                log=evidence/(theme+'.log');log.write_text(value.stdout+value.stderr)
                result['checks'].append({'name':'offline-'+theme,'command':command,'cwd':str(root),
                    'startedAt':started,'completedAt':now(),'exit':value.returncode,'log':str(log)})
                assert value.returncode==0, 'installed offline GUI failed'
                assert 'OFFLINE guard: IPv4/IPv6/Unix socket creation denied EPERM' in value.stdout
                assert 'font=Inter' in value.stdout and f'GUI assets: font={prefix}/share/quietproof/fonts/Inter.ttf renderer=software' in value.stdout
                assert 'GUI request: loaded=1 error=0' in value.stdout
                assert value.stdout.count('GUI proof stage: 5')==1, 'exact public proof not natively verified'
                assert destination.read_bytes()==proof.read_bytes() and replaced.read_bytes()==proof.read_bytes()
                assert destination.stat().st_mode & 0o777 == 0o600 and replaced.stat().st_mode & 0o777 == 0o600
                assert not list(root.rglob('.quietproof-*')), 'temporary output survived'
                rows=re.findall(r'^GUI capture: (\d+) retained=(\d) confirm=(\d) dialog=(\d) busy=(\d) status=(\d)$',value.stdout,re.M)
                assert len(rows)==5 and all(row[1]=='1' and row[4]=='0' for row in rows)
                assert rows[3][2]=='1' and rows[4][2]=='0', 'overwrite identity approval missing'
                controls={}
                for row in re.findall(r'^GUI capture control: (\d+) (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',value.stdout,re.M):
                    controls.setdefault(int(row[0]),{})[int(row[1])]=tuple(map(float,row[2:]))
                for row in rows:
                    for identifier in ((307,308) if row[3]=='1' else (11,)):
                        x,y,w,h=controls[int(row[0])][identifier]
                        assert 0<=x<x+w<=size[0] and 0<=y<y+h<=size[1], 'installed primary action clipped'
                for suffix in ('result','failure','saved','approval','replaced'):
                    image=evidence/f'{theme}-{suffix}.bmp'
                    dimensions=struct.unpack_from('<ii',image.read_bytes(),18)
                    assert dimensions==(size[0]*pixel,size[1]*pixel)
                    result['screenshots'].append({'path':str(image),'theme':theme,'fontScale':font,'pixelScale':pixel,
                        'logicalWidth':size[0],'logicalHeight':size[1],'pixelWidth':dimensions[0],'pixelHeight':dimensions[1],
                        'display':'SDL dummy/software; seccomp all sockets denied'})
                (evidence/(theme+'-saved.qpf')).write_bytes(destination.read_bytes())
        result.update(status='passed', executed=4, passed=4, failed=0, skipped=0)
    except BaseException:
        result.update(status='failed', failed=1)
        raise
    finally:
        result.update(completedAt=now(), ownedProcesses=[])
        (evidence/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Installed package: asset identities +2 offline verified-save/retry/overwrite scenarios passed; owned processes0')


if __name__=='__main__':
    main()
