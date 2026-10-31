"""Real Roots request/node/private-input layout matrix; no unlock or new proof."""
import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'quietproof'))
from regtest_rpc_test import Node, require


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--roots',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    binaries,build,evidence=(p.resolve() for p in (args.roots,args.build,args.evidence))
    evidence.mkdir(parents=True,exist_ok=False)
    gui,cli=build/'quietproof-prover-gui',build/'quietproof'
    result={'startedAt':now(),'checks':[],'screenshots':[],'status':'running','ownedProcesses':[],
            'display':'SDL dummy/software','nativeProofs':0,'unlockSubmissions':0}
    def save():
        (evidence/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    save()
    with tempfile.TemporaryDirectory(prefix='quietproof-masked-matrix-') as temporary:
        root=Path(temporary);root.chmod(0o700)
        node=Node(binaries,root/'node')
        env=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=str(root),HOME=str(root))
        password=''.join(chr(65+i) for i in range(12))
        def run(name,command,timeout=20):
            command=list(map(str,command));started=now()
            value=subprocess.run(command,env=env,capture_output=True,text=True,timeout=timeout)
            output=value.stdout+value.stderr
            require(password not in output,'private synthetic input reached diagnostics')
            cookie=node.cookie.read_text().strip()
            require(cookie not in output,'cookie reached diagnostics')
            path=evidence/(name+'.log');path.write_text(output)
            result['checks'].append({'name':name,'command':command,'cwd':os.getcwd(),'startedAt':started,
                'completedAt':now(),'exit':value.returncode,'log':str(path),'logBytes':path.stat().st_size,
                'logSha256':hashlib.sha256(path.read_bytes()).hexdigest()})
            save();require(value.returncode==0,name+': native command failed')
            return value
        try:
            node.start()
            result['ownedProcesses']=[node.process.pid]
            result['node']={'command':node.process.args,'pid':node.process.pid,'binary':str(binaries/'bitcoind'),
                'sha256':hashlib.sha256((binaries/'bitcoind').read_bytes()).hexdigest(),
                'version':node.call('getnetworkinfo')['subversion'],'chain':node.call('getblockchaininfo')['chain']}
            require(result['node']['chain']=='regtest','node is not isolated regtest')
            wallet='matrix-encrypted'
            node.call('createwallet',wallet,False,False,password)
            address=node.call('getnewaddress','','bech32',wallet=wallet)
            first=node.call('generatetoaddress',101,address)[0]
            transaction=node.call('getblock',first,2)['tx'][0]
            coin=next(v for v in transaction['vout'] if v['scriptPubKey'].get('address')==address)
            amount=int(round(coin['value']*100000000))
            program=coin['scriptPubKey']['hex'][4:]
            require(len(program)==40 and coin['scriptPubKey']['hex']=='0014'+program,'real P2WPKH output missing')
            request=root/'matrix.qpr'
            run('request',[cli,'challenge','create','--network','regtest','--claim',
                f"{transaction['txid']}:{coin['n']}:{amount}:{program}",'--verifier','matrix.example',
                '--purpose','proof-of-control','--expires-in','86400','--output',request])
            (evidence/'matrix.qpr').write_bytes(request.read_bytes())
            preferences=root/'Plan-B/quietproof';preferences.mkdir(parents=True,exist_ok=True)
            fields=['127.0.0.1',str(node.port),'',str(node.cookie),wallet,'3000','3000']
            configuration='quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(fields))
            settings=preferences/'node.conf';settings.write_text(configuration);settings.chmod(0o600)
            require(node.call('getwalletinfo',wallet=wallet)['unlocked_until']==0,'matrix wallet initially unlocked')
            for theme,size,font,pixel in itertools.product(('light','dark'),((400,640),(480,720),(600,900)),('1','1.25','1.5'),(1,2)):
                name=f'{theme}-{size[0]}x{size[1]}-font{font}-pixel{pixel}'
                shots=[]
                def shot(view):
                    path=evidence/(view+'-'+name+'.bmp')
                    shots.append({'name':view+'-'+name,'view':view,'path':str(path),'theme':theme,
                        'logicalWidth':size[0],'logicalHeight':size[1],'fontScale':font,'pixelScale':pixel})
                    return 'capture '+str(path)
                events=[shot('request'),'control 3','control 11']+['wait']*20+[shot('node'),
                    'control 2','control 304']+['wait']*20+['private-synthetic','copy','cut','paste','undo','redo',
                    'tab','backtab','pagedown',shot('masked')]
                script=evidence/(name+'.events');script.write_text('\n'.join(events)+'\n')
                value=run(name,[gui,'--smoke-test','--request',request,'--theme',theme,'--font-scale',font,
                    '--width',str(size[0]),'--height',str(size[1]),'--pixel-scale',str(pixel),'--test-events',script])
                require(re.search(r'GUI wallet: prompt=1 masked=1 cleared=1 busy=0 focus=0 scroll=\d+',value.stdout),
                        name+': masked-input ownership or keyboard focus failed')
                require(re.search(r'GUI probe: .*complete=1 selected=1 error=0',value.stdout),name+': real wallet probe did not settle')
                require('GUI proof stage: 3' not in value.stdout and 'GUI proof: canceled=0 generated=0' in value.stdout,
                        name+': matrix unexpectedly entered native proving')
                if size==(400,640) and font=='1.5':
                    require(int(re.search(r'GUI wallet: .*scroll=(\d+)',value.stdout)[1])>0,name+': private information did not scroll')
                rows=re.findall(r'^GUI capture: (\d+) retained=(\d) confirm=(\d) dialog=(\d) busy=(\d) status=(\d)$',value.stdout,re.M)
                require(len(rows)==3,name+': capture identities differ')
                controls={}
                for row in re.findall(r'^GUI capture control: (\d+) (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',value.stdout,re.M):
                    controls.setdefault(int(row[0]),{})[int(row[1])]=tuple(map(float,row[2:]))
                # Per-capture metadata exposes fixed Save controls only. The
                # final masked capture shares the unchanged terminal layout.
                terminal={int(row[0]):tuple(map(float,row[1:])) for row in re.findall(
                    r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',value.stdout,re.M)}
                for row,record in zip(rows,shots):
                    index=int(row[0]);bounds=terminal if record['view']=='masked' else controls[index]
                    record.update(captureIndex=index,controls=bounds,command=name)
                    for identifier in ((301,302,303) if record['view']=='masked' else (11,)):
                        x,y,w,h=bounds[identifier]
                        require(0<=x<x+w<=size[0] and 0<=y<y+h<=size[1],name+': primary action clipped')
                    raw=Path(record['path']).read_bytes();dimensions=struct.unpack_from('<ii',raw,18)
                    require(dimensions==(size[0]*pixel,size[1]*pixel),name+': screenshot dimensions differ')
                    record.update(width=dimensions[0],height=dimensions[1],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                result['screenshots']+=shots
                require(settings.read_text()==configuration,'private matrix changed saved node settings')
                require(node.call('getwalletinfo',wallet=wallet)['unlocked_until']==0,'masked-only matrix changed lock state')
                save()
            result.update(status='passed',executed=len(result['checks']),passed=len(result['checks']),failed=0,skipped=0)
        except BaseException as error:
            result.update(status='failed',failure={'type':type(error).__name__,
                'message':str(error) if isinstance(error,RuntimeError) else 'qualification interrupted; inspect original command'})
            raise
        finally:
            node.stop();password=''
            result.update(ownedProcesses=[],nodeReaped=node.process is None,completedAt=now());save()
    print('Real Roots UI:36 request/node/masked combinations,108 native captures; no unlock/proof; owned processes=0')


if __name__=='__main__':
    main()
