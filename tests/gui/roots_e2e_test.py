"""Explicit opt-in Roots qualification with disposable, loopback-only regtest wallets.

No default node, user wallet, downloaded binary, password argument or private
transcript is used. Password input uses the GUI's transient synthetic SDL event.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import secrets
import select
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'quietproof'))
from regtest_rpc_test import Node, require


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def virtual_display(root, environment):
    """Own Xvfb directly; xauth is unnecessary and authority bytes stay private."""
    authority = root/'x11-authority'
    cookie = secrets.token_bytes(16)
    def write_authority(number):
        fields = (b'',number,b'MIT-MAGIC-COOKIE-1',cookie)
        authority.write_bytes(struct.pack('>H',65535)+b''.join(struct.pack('>H',len(v))+v for v in fields))
        authority.chmod(0o600)
    write_authority(b'0')
    read, write = os.pipe()
    process = None
    previous = {k:environment.get(k) for k in ('DISPLAY','XAUTHORITY','SDL_VIDEODRIVER')}
    try:
        process = subprocess.Popen(['Xvfb','-displayfd',str(write),'-auth',str(authority),
            '-screen','0','1024x1200x24','-nolisten','tcp'],pass_fds=(write,),
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        os.close(write); write = None
        require(select.select([read],[],[],10)[0], 'owned Xvfb startup deadline exceeded')
        number = os.read(read,32).strip()
        require(number.isdigit() and process.poll() is None, 'owned Xvfb startup failed')
        write_authority(number)
        environment.update(DISPLAY=':'+number.decode(),XAUTHORITY=str(authority),SDL_VIDEODRIVER='x11')
        yield
    finally:
        os.close(read)
        if write is not None: os.close(write)
        if process is not None:
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        for key,value in previous.items():
            if value is None: environment.pop(key,None)
            else: environment[key]=value
        authority.unlink(missing_ok=True)


def platform_checks(args):
    """Focused continuation after a setup-only display failure; no new proof."""
    evidence=args.evidence.resolve(); evidence.mkdir(parents=True,exist_ok=False)
    build=args.build.resolve(); request=args.public_request.resolve()
    result={'startedAt':now(),'checks':[],'screenshots':[],'status':'running','ownedProcesses':[]}
    with tempfile.TemporaryDirectory(prefix='quietproof-platform-') as temporary:
        root=Path(temporary); root.chmod(0o700)
        env=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=str(root),HOME=str(root))
        node=Node(args.core.resolve(),root/'core')
        def run(name,events):
            script=evidence/(name+'.events');script.write_text('\n'.join(events)+'\n')
            image=evidence/(name+'.bmp')
            command=[str(build/'quietproof-prover-gui'),'--smoke-test','--request',str(request),
                '--theme','light','--font-scale','1','--test-events',str(script),'--screenshot',str(image)]
            started=now(); value=subprocess.run(command,env=env,capture_output=True,text=True,timeout=30)
            (evidence/(name+'.log')).write_text(value.stdout+value.stderr)
            result['checks'].append({'name':name,'command':command,'cwd':os.getcwd(),'startedAt':started,
                'completedAt':now(),'exit':value.returncode,'log':str(evidence/(name+'.log'))})
            require(value.returncode==0,name+': native GUI failed')
            result['screenshots'].append({'name':name,'path':str(image),'theme':'light','logicalWidth':480,
                'logicalHeight':720,'fontScale':'1','pixelScale':1,'display':'owned Xvfb/software' if name.startswith('virtual') else 'SDL dummy/software'})
            return value
        try:
            with virtual_display(root,env): run('virtual-x11-review',['tab','backtab','pagedown','pageup'])
            result['xvfbReaped']=True
            node.start();result['ownedProcesses']=[node.process.pid]
            node.call('createwallet','core')
            miner=node.call('getnewaddress','','bech32',wallet='core')
            node.call('generatetoaddress',101,miner)
            result['core']={'binary':str(args.core.resolve()/'bitcoind'),
                'sha256':hashlib.sha256((args.core.resolve()/'bitcoind').read_bytes()).hexdigest(),
                'version':node.call('getnetworkinfo')['subversion'],'chain':node.call('getblockchaininfo')['chain']}
            preferences=root/'Plan-B/quietproof';preferences.mkdir(parents=True,exist_ok=True)
            fields=['127.0.0.1',str(node.port),'',str(node.cookie),'core','3000','3000']
            settings=preferences/'node.conf';settings.write_text('quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(fields)));settings.chmod(0o600)
            value=run('core-unsupported',['control 3','control 11']+['wait']*25)
            require(re.search(r'GUI probe: .*complete=1 selected=0 error=0',value.stdout),'Core capability rejection absent')
            result.update(status='passed',executed=2,passed=2,failed=0,skipped=0)
        finally:
            node.stop();result.update(ownedProcesses=[],nodeReaped=node.process is None,completedAt=now())
            (evidence/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Platform: virtual X11 and real Core capability checks passed; all owned processes reaped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roots', type=Path, required=True, help='Existing Roots bin directory')
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--core', type=Path, required=True, help='Existing Core bin directory for capability detection')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--platform-only',action='store_true',help='Run focused virtual-display/Core continuation without repeating proofs')
    parser.add_argument('--public-request',type=Path,help='Existing public request for --platform-only')
    args = parser.parse_args()
    if args.platform_only:
        require(args.public_request is not None and args.public_request.is_file(),'platform continuation requires a public request')
        platform_checks(args)
        return
    binaries, build, evidence = (p.resolve() for p in (args.roots, args.build, args.evidence))
    evidence.mkdir(parents=True, exist_ok=False)
    gui, cli = build/'quietproof-prover-gui', build/'quietproof'
    driver = build/'src/gui/quietproof-gui-proof-output-test'
    for path in (binaries/'bitcoind', gui, cli, driver):
        require(path.is_file() and os.access(path, os.X_OK), 'explicit executable unavailable')
    manifest = {'startedAt': now(), 'checks': [], 'screenshots': [], 'ownedProcesses': [],
                'node': {'binary': str(binaries/'bitcoind'),
                         'sha256': hashlib.sha256((binaries/'bitcoind').read_bytes()).hexdigest()},
                'display': 'SDL dummy/software; no physical display claim', 'status': 'running'}
    def save():
        (evidence/'summary.json').write_text(json.dumps(manifest, indent=2)+'\n')
    save()
    # This public synthetic test input is constructed only in transient buffers.
    # Neither its plaintext nor cookie values are written to the evidence.
    password = ''.join(chr(65+i) for i in range(12))
    with tempfile.TemporaryDirectory(prefix='quietproof-roots-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        node = Node(binaries, root/'node')
        environment = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
                           XDG_DATA_HOME=str(root/'preferences'), HOME=str(root))
        preference = root/'preferences/Plan-B/quietproof'
        preference.mkdir(parents=True)
        def settings(wallet=''):
            values = ['127.0.0.1', str(node.port), '', str(node.cookie), wallet, '3000', '3000']
            text = 'quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(values))
            path = preference/'node.conf'
            path.write_text(text)
            path.chmod(0o600)
            return text
        def run(name, command, timeout=240, expected=0):
            started = now()
            command=list(map(str,command))
            observation = None
            if name=='encrypted-workflow':
                # Sample lock state at Prove entry, before the requested15s
                # lease could expire. After a long proof, expiry alone could
                # otherwise explain a locked wallet and hide missing cleanup.
                tick=time.monotonic(); captured=bytearray()
                process=subprocess.Popen(command,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    while b'GUI proof stage: 3 ' not in captured and time.monotonic()-tick<14:
                        if select.select([process.stdout],[],[],.1)[0]:
                            chunk=os.read(process.stdout.fileno(),4096)
                            if not chunk: break
                            captured.extend(chunk)
                    require(b'GUI proof stage: 3 ' in captured,'encrypted proof entry observation unavailable before lease deadline')
                    locked=node.call('getwalletinfo',wallet='encrypted')['unlocked_until']==0
                    elapsed=time.monotonic()-tick
                    observation={'observedAt':now(),'lockedAtProveEntry':locked,'secondsSinceGuiLaunch':elapsed,
                                 'requestedUnlockSeconds':15,'sampledBeforeEarliestLeaseExpiry':elapsed<15}
                    require(locked and elapsed<15,'encrypted wallet not relocked before lease expiry')
                    stdout,stderr=process.communicate(timeout=timeout)
                    value=subprocess.CompletedProcess(command,process.returncode,(captured+stdout).decode(),stderr.decode())
                finally:
                    if process.poll() is None: process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            else:
                value = subprocess.run(command, env=environment, capture_output=True,text=True,timeout=timeout)
            output = value.stdout+value.stderr
            require(password not in output, 'private input reached process diagnostics')
            cookie = node.cookie.read_text().strip() if node.cookie.exists() else None
            require(not cookie or cookie not in output, 'cookie reached process diagnostics')
            path = evidence/(name+'.log')
            path.write_text(output)
            manifest['checks'].append({'name': name, 'command': list(map(str, command)),
                'cwd': os.getcwd(), 'startedAt': started, 'completedAt': now(), 'exit': value.returncode,
                'expectedExit': expected, 'log': str(path), 'logBytes': path.stat().st_size,
                'logSha256': hashlib.sha256(path.read_bytes()).hexdigest(),'leaseObservation':observation})
            save()
            require(value.returncode == expected, f'{name}: unexpected exit {value.returncode}')
            return value
        def ui(name, request, events, pixel=1):
            script = evidence/(name+'.events')
            script.write_text('\n'.join(events)+'\n')
            result = run(name, [gui, '--smoke-test', '--request', request, '--test-events', script,
                               '--theme','light','--font-scale','1',
                               '--width', '480', '--height', '720', '--pixel-scale', str(pixel)], timeout=360)
            captures = re.findall(r'^GUI capture: (\d+) retained=(\d) confirm=(\d) dialog=(\d) busy=(\d) status=(\d)$',result.stdout,re.M)
            controls = {}
            for row in re.findall(r'^GUI capture control: (\d+) (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',result.stdout,re.M):
                controls.setdefault(int(row[0]),{})[int(row[1])]=tuple(map(float,row[2:]))
            selected = [s for s in manifest['screenshots'] if 'captureIndex' not in s]
            require(len(captures)==len(selected), 'capture selection differs from requested identities')
            for row,shot in zip(captures,selected):
                index,retained,confirmed,dialog,busy,status=map(int,row)
                shot.update(captureIndex=index,retained=retained,confirm=confirmed,dialog=dialog,busy=busy,status=status,
                            controls=controls.get(index,{}),command=name)
                if name.startswith('matrix-'):
                    require(retained==1 and busy==0, 'public proof lost or layout worker not settled')
                    for identifier in ((307,308) if dialog else (11,)):
                        x,y,w,h=controls[index][identifier]
                        require(0<=x<x+w<=shot['logicalWidth'] and 0<=y<y+h<=shot['logicalHeight'],
                                'primary layout action clipped')
            save()
            return result
        def capture(events, name, theme='light', size=(480,720), font='1', pixel=1):
            path = evidence/(name+'.bmp')
            events.append('capture '+str(path))
            manifest['screenshots'].append({'name':name, 'path':str(path), 'theme':theme,
                'logicalWidth':size[0], 'logicalHeight':size[1], 'fontScale':font, 'pixelScale':pixel})
        opening = ['control 3', 'control 11']+['wait']*20+['control 2', 'control 304']
        try:
            node.start()
            manifest['ownedProcesses'] = [node.process.pid]
            manifest['node'].update(command=node.process.args,pid=node.process.pid)
            manifest['node'].update(version=node.call('getnetworkinfo')['subversion'],
                                    chain=node.call('getblockchaininfo')['chain'])
            require(manifest['node']['chain']=='regtest', 'node isolation failed')
            node.call('createwallet', 'plain')
            node.call('createwallet', 'encrypted', False, False, password)
            miner = node.call('getnewaddress', '', 'bech32', wallet='plain')
            node.call('generatetoaddress', 101, miner)
            requests, coins = {}, {}
            manifest['walletScenarios']={}
            for wallet in ('plain', 'encrypted'):
                script_kind='p2pkh' if wallet=='plain' else 'p2wpkh'
                address = node.call('getnewaddress', '', 'legacy' if wallet=='plain' else 'bech32', wallet=wallet)
                txid = node.call('sendtoaddress', address, 1, wallet='plain')
                block = node.call('generatetoaddress', 1, miner)[0]
                transaction = node.call('getrawtransaction', txid, True, block)
                coin = next(v for v in transaction['vout'] if v['scriptPubKey'].get('address')==address)
                script = coin['scriptPubKey']['hex']
                program = script[6:-4] if script_kind=='p2pkh' else script[4:]
                require(len(program)==40 and script==('76a914'+program+'88ac' if script_kind=='p2pkh' else '0014'+program),
                        'funded script differs from selected scenario')
                claim=f"{txid}:{coin['n']}:100000000:"+(script_kind+':' if script_kind=='p2pkh' else '')+program
                request = root/(wallet+'.qpr')
                run(wallet+'-request', [cli, 'challenge', 'create', '--network', 'regtest',
                    '--claim', claim, '--verifier', 'roots-e2e.example',
                    '--purpose', 'proof-of-control', '--message', 'Isolated Roots qualification',
                    '--expires-in', '86400', '--output', request])
                requests[wallet] = request
                coins[wallet] = {'txid':txid,'vout':coin['n'],'address':address}
                manifest['walletScenarios'][wallet]={'scriptKind':script_kind,'encrypted':wallet=='encrypted',
                    'statementVersion':2 if script_kind=='p2pkh' else 1,'claim':claim}
                (evidence/(wallet+'.qpr')).write_bytes(request.read_bytes())
            require(node.call('getwalletinfo', wallet='encrypted')['unlocked_until']==0,
                    'encrypted wallet not locked before GUI use')
            for wallet in ('plain','encrypted'):
                config = settings(wallet)
                request = requests[wallet]
                proof = root/(wallet+'.qpf')
                events = list(opening)
                if wallet=='encrypted':
                    events += ['wait']*20
                    capture(events, 'encrypted-locked')
                    events += ['private-synthetic','backspace','enter']+['wait']*20
                    capture(events, 'encrypted-wrong-password')
                    events += ['private-synthetic','enter']
                events += ['await-proof']
                capture(events, wallet+'-success')
                events += ['control 11','destination '+str(proof),'control 307','await-save']
                capture(events, wallet+'-saved')
                result = ui(wallet+'-workflow', request, events)
                require(result.stdout.count('GUI proof stage: 5')==1, 'native verification not observed once')
                require(proof.exists() and proof.stat().st_mode & 0o777 == 0o600, 'proof save/mode failed')
                require((preference/'node.conf').read_text()==config, 'GUI changed connection settings')
                if wallet=='encrypted':
                    require(node.call('getwalletinfo', wallet=wallet)['unlocked_until']==0,
                            'owned wallet unlock was not relocked')
                else:
                    require('unlocked_until' not in node.call('getwalletinfo', wallet=wallet),
                            'unencrypted wallet state changed')
                extracted = root/(wallet+'-extracted.qpr')
                run(wallet+'-extract', [driver, proof, extracted, '--prepare-request'])
                require(extracted.read_bytes()==request.read_bytes(), 'GUI changed exact reviewed request')
                value=run(wallet+'-verify', [cli,'verify',proof,'--verifier','roots-e2e.example',
                    '--purpose','proof-of-control','--network','regtest','--nonce-store',root/(wallet+'.nonces'),
                    '--rpc-url',node.url,'--rpc-cookie',node.cookie],timeout=180)
                require(json.loads(value.stdout)['result']=='valid_current', 'real-chain verification failed')
                run(wallet+'-wrong-network', [cli,'verify',proof,'--verifier','roots-e2e.example',
                    '--purpose','proof-of-control','--network','signet','--nonce-store',root/(wallet+'-wrong.nonces'),
                    '--rpc-url',node.url,'--rpc-cookie',node.cookie],expected=67)
                (evidence/(wallet+'.qpf')).write_bytes(proof.read_bytes())
            # The exact proved outpoint is spent on the owned chain. A public
            # cryptographic proof must not authorize a current-chain claim now.
            coin=coins['plain']
            raw=node.call('createrawtransaction',[{'txid':coin['txid'],'vout':coin['vout']}],{miner:0.9999})
            signed=node.call('signrawtransactionwithwallet',raw,wallet='plain')
            require(signed['complete'], 'owned test spend signing failed')
            node.call('sendrawtransaction',signed['hex'])
            spent=run('plain-spent-outpoint',[cli,'verify',root/'plain.qpf','--verifier','roots-e2e.example',
                '--purpose','proof-of-control','--network','regtest','--nonce-store',root/'spent.nonces',
                '--rpc-url',node.url,'--rpc-cookie',node.cookie],timeout=180,expected=5)
            require(json.loads(spent.stdout)['result']=='state_inconclusive' and not (root/'spent.nonces').exists(),
                    'spent outpoint accepted or consumed replay nonce')
            # The verified public proof is reused for layout/retry qualification.
            for pixel in (1,2):
                events=['proof-fixture '+str(evidence/'plain.qpf'),'await-proof']
                for theme,size,font in itertools.product(('light','dark'),((400,640),(480,720),(600,900)),('1','1.25','1.5')):
                    name=f'matrix-{theme}-{size[0]}x{size[1]}-font{font}-pixel{pixel}'
                    events += [f'resize {size[0]} {size[1]}','control 1','control '+('5' if theme=='light' else '6'),
                               'control '+{'1':'7','1.25':'8','1.5':'9'}[font],'control 11','control 4']
                    capture(events,name+'-result',theme,size,font,pixel)
                    events += ['control 11','tab','backtab','pagedown','pageup']
                    capture(events,name+'-save',theme,size,font,pixel)
                    events += ['control 308']
                ui('matrix-pixel'+str(pixel),requests['plain'],events,pixel)
            # Cancellation before submitting a password cannot acquire an unlock.
            settings('encrypted')
            events=opening+['wait']*20+['private-synthetic','escape']+['wait']*10
            capture(events,'encrypted-cancel')
            ui('encrypted-cancel',requests['encrypted'],events)
            require(node.call('getwalletinfo',wallet='encrypted')['unlocked_until']==0,
                    'cancel changed locked wallet state')
            # Real watch-only wallet: capability rejection must leave proving disabled.
            node.call('createwallet','watch',True,True)
            descriptor=node.call('getaddressinfo',coins['plain']['address'],wallet='plain')['desc']
            imported=node.call('importdescriptors',[{'desc':descriptor,'timestamp':'now'}],wallet='watch')
            require(imported[0]['success'], 'watch-only public descriptor setup failed')
            settings('watch')
            events=['control 3','control 11']+['wait']*25+['end']
            capture(events,'roots-watch-only')
            unsupported=ui('roots-watch-only',requests['plain'],events)
            require(re.search(r'GUI probe: .*complete=1 selected=0 error=0',unsupported.stdout),
                    'watch-only wallet unexpectedly eligible')
            # Virtual X11 is separate from the dummy-driver matrix. Its owned
            # server has private authority data and no TCP listener.
            with virtual_display(root,environment):
                script=evidence/'xvfb-review.events'
                script.write_text('tab\nbacktab\npagedown\npageup\n')
                run('virtual-x11-review',[gui,'--smoke-test','--request',requests['plain'],'--test-events',script,
                    '--theme','light','--font-scale','1',
                    '--screenshot',evidence/'virtual-x11-review.bmp'])
                manifest['screenshots'].append({'name':'virtual-x11-review','path':str(evidence/'virtual-x11-review.bmp'),
                    'theme':'light','logicalWidth':480,'logicalHeight':720,'fontScale':'1','pixelScale':1,
                    'captureIndex':0,'command':'virtual-x11-review','display':'Xvfb virtual X11/software'})
            node.stop()
            manifest['rootsReaped']=node.process is None
            # Full Core proving is intentionally deferred; a fresh owned Core
            # regtest instance must report that exportaddresskey is unsupported.
            core=args.core.resolve()
            manifest['core']={'binary':str(core/'bitcoind'),
                              'sha256':hashlib.sha256((core/'bitcoind').read_bytes()).hexdigest()}
            node=Node(core,root/'core-node')
            node.start()
            manifest['ownedProcesses']=[node.process.pid]
            manifest['core'].update(command=node.process.args,pid=node.process.pid)
            manifest['core'].update(version=node.call('getnetworkinfo')['subversion'],chain=node.call('getblockchaininfo')['chain'])
            node.call('createwallet','core')
            core_miner=node.call('getnewaddress','','bech32',wallet='core')
            node.call('generatetoaddress',101,core_miner)
            settings('core')
            events=['control 3','control 11']+['wait']*25
            capture(events,'core-unsupported')
            unsupported=ui('core-unsupported',requests['plain'],events)
            require(re.search(r'GUI probe: .*complete=1 selected=0 error=0',unsupported.stdout),
                    'Core capability probe did not reject unsupported proving')
            for shot in manifest['screenshots']:
                path=Path(shot['path']); raw=path.read_bytes()
                width,height=struct.unpack_from('<ii',raw,18)
                require((width,height)==(shot['logicalWidth']*shot['pixelScale'],shot['logicalHeight']*shot['pixelScale']),
                        'native capture dimensions differ from selected matrix')
                shot.update(width=width,height=height,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            manifest.update(status='passed',executed= len(manifest['checks']),failed=0,skipped=0)
        except BaseException as error:
            manifest.update(status='failed',failure={'type':type(error).__name__,
                'message':str(error) if isinstance(error,RuntimeError) else 'qualification interrupted; see original check'})
            raise
        finally:
            node.stop()
            password = ''
            manifest.update(ownedProcesses=[],completedAt=now(),nodeReaped=node.process is None)
            save()
    print(f"Roots GUI: {manifest['executed']} commands passed; {len(manifest['screenshots'])} native captures; owned processes=0",flush=True)


if __name__=='__main__':
    main()
