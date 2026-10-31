"""Opt-in installed Linux GUI/CLI roundtrip with one owned encrypted Roots wallet.

The repository Node/Xvfb helpers are qualification-only; the installed product
contains no Python helper or source-tree runtime dependency.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
from roots_e2e_test import Node, virtual_display, require


def now(): return datetime.now(timezone.utc).isoformat()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ('prefix','roots','driver','evidence'):
        parser.add_argument('--'+field,type=Path,required=True)
    args=parser.parse_args()
    prefix,roots,driver,evidence=(p.resolve() for p in (args.prefix,args.roots,args.driver,args.evidence))
    evidence.mkdir(parents=True,exist_ok=False)
    gui,cli=prefix/'bin/quietproof-prover-gui',prefix/'bin/quietproof'
    result={'startedAt':now(),'checks':[],'screenshots':[],'status':'running','ownedProcesses':[],
        'qualificationOnlyHelper':str(driver),'installedPrefix':str(prefix)}
    password=''.join(chr(65+i) for i in range(12))
    with tempfile.TemporaryDirectory(prefix='quietproof-installed-roots-') as temporary:
        root=Path(temporary);root.chmod(0o700)
        node=Node(roots,root/'node')
        environment=dict(os.environ,HOME=str(root/'home'),XDG_DATA_HOME=str(root/'data'),
            XDG_CONFIG_HOME=str(root/'config'),XDG_CACHE_HOME=str(root/'cache'),SDL_RENDER_DRIVER='software')
        (root/'home').mkdir()
        for key in ('DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','LD_LIBRARY_PATH'):
            environment.pop(key,None)
        def run(name,command,timeout=240):
            command=list(map(str,command));started=now()
            value=subprocess.run(command,cwd=root,env=environment,capture_output=True,text=True,timeout=timeout,close_fds=True)
            output=value.stdout+value.stderr
            cookie=node.cookie.read_text().strip() if node.cookie.exists() else ''
            require(password not in output and (not cookie or cookie not in output),'private material reached diagnostics')
            log=evidence/(name+'.log');log.write_text(output)
            result['checks'].append({'name':name,'command':command,'cwd':str(root),'startedAt':started,
                'completedAt':now(),'exit':value.returncode,'log':str(log)})
            require(value.returncode==0,name+': unexpected exit')
            return value
        try:
            node.start();result['ownedProcesses']=[node.process.pid]
            result['node']={'binary':str(roots/'bitcoind'),'sha256':hashlib.sha256((roots/'bitcoind').read_bytes()).hexdigest(),
                'command':node.process.args,'version':node.call('getnetworkinfo')['subversion'],
                'chain':node.call('getblockchaininfo')['chain']}
            require(result['node']['chain']=='regtest','isolated node chain mismatch')
            node.call('createwallet','miner')
            node.call('createwallet','encrypted',False,False,password)
            miner=node.call('getnewaddress','','bech32',wallet='miner')
            node.call('generatetoaddress',101,miner)
            address=node.call('getnewaddress','','bech32',wallet='encrypted')
            txid=node.call('sendtoaddress',address,1,wallet='miner')
            block=node.call('generatetoaddress',1,miner)[0]
            transaction=node.call('getrawtransaction',txid,True,block)
            coin=next(v for v in transaction['vout'] if v['scriptPubKey'].get('address')==address)
            script=coin['scriptPubKey']['hex'];require(script.startswith('0014') and len(script)==44,'unexpected funded script')
            claim=f"{txid}:{coin['n']}:100000000:{script[4:]}"
            request=evidence/'installed.qpr';proof=evidence/'installed.qpf'
            run('create-request',[cli,'challenge','create','--network','regtest','--claim',claim,
                '--verifier','installed.example','--purpose','proof-of-control','--message','Isolated installed GUI qualification',
                '--expires-in','86400','--output',request])
            preferences=root/'data/Plan-B/quietproof';preferences.mkdir(parents=True)
            fields=['127.0.0.1',str(node.port),'',str(node.cookie),'encrypted','3000','3000']
            settings=preferences/'node.conf';settings.write_text('quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(fields)));settings.chmod(0o600)
            events=['capture '+str(evidence/'installed-review.bmp'),'control 3','control 11']+['wait']*20+[
                'control 2','control 304']+['wait']*20+['capture '+str(evidence/'installed-unlock.bmp'),
                'private-synthetic','enter','await-proof','capture '+str(evidence/'installed-result.bmp'),
                'control 11','destination '+str(proof),'control 307','await-save','capture '+str(evidence/'installed-save.bmp')]
            events_file=evidence/'installed.events';events_file.write_text('\n'.join(events)+'\n')
            require(node.call('getwalletinfo',wallet='encrypted')['unlocked_until']==0,'wallet not initially locked')
            with virtual_display(root,environment):
                value=run('installed-wallet-workflow',[gui,'--smoke-test','--request',request,'--theme','light',
                    '--font-scale','1','--width','480','--height','720','--test-events',events_file],timeout=360)
            result['xvfbReaped']=True
            require(f'GUI assets: font={prefix}/share/quietproof/fonts/Inter.ttf renderer=software' in value.stdout,'installed font/renderer identity differs')
            require(value.stdout.count('GUI proof stage: 5')==1 and 'GUI proof stage: 3' in value.stdout,'normal native prove/verify stages absent')
            require(node.call('getwalletinfo',wallet='encrypted')['unlocked_until']==0,'owned wallet not relocked')
            require(proof.is_file() and proof.stat().st_mode & 0o777 == 0o600,'installed proof save failed')
            extracted=evidence/'extracted.qpr'
            run('extract-exact-request',[driver,proof,extracted,'--prepare-request'])
            require(extracted.read_bytes()==request.read_bytes(),'installed proof differs from reviewed request')
            value=run('verify-current',[cli,'verify',proof,'--network','regtest','--verifier','installed.example',
                '--purpose','proof-of-control','--nonce-store',root/'nonces','--rpc-url',node.url,'--rpc-cookie',node.cookie])
            require(json.loads(value.stdout)['result']=='valid_current','installed CLI did not verify exact current outpoint')
            for name in ('review','unlock','result','save'):
                result['screenshots'].append({'path':str(evidence/f'installed-{name}.bmp'),'theme':'light','fontScale':'1',
                    'pixelScale':1,'logicalWidth':480,'logicalHeight':720,'display':'owned authenticated Xvfb/software'})
            result.update(status='passed',executed=4,passed=4,failed=0,skipped=0)
        except BaseException:
            result.update(status='failed',failed=1)
            raise
        finally:
            node.stop();result.update(completedAt=now(),ownedProcesses=[],nodeReaped=node.process is None)
            (evidence/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Installed Roots encrypted GUI proof/save + exact request + installed CLI valid_current passed; owned processes0')

if __name__=='__main__':main()
