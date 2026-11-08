"""Actual v4 GUI profile proofs and native text/layout evidence; no wallet access."""
import hashlib
import json
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import time
from signature_session_fixture import fixtures

gui,driver,cli,artifacts=map(lambda x:Path(x).resolve(),sys.argv[1:5])
artifacts=artifacts/f'run-{time.time_ns()}-{os.getpid()}'
artifacts.mkdir(parents=True,exist_ok=False,mode=0o700)
private=artifacts/'private';private.mkdir(exist_ok=True,mode=0o700)
records=[];proofs=[]
layouts=[(400,760),(1100,900)]

def run(profile,name,size=(400,760),scale='1',events=(),extra=(),loaded=True):
    root=private/profile
    script=artifacts/(name+'.events');script.write_text('\n'.join(events)+('\n' if events else ''))
    image=artifacts/(name+'.bmp')
    command=[str(gui),'--smoke-test','--request',str(root/'request.qpr'),'--receipt-input',str(root/'receipt.qpa'),
             '--width',str(size[0]),'--height',str(size[1]),'--font-scale',scale,
             '--test-events',str(script),'--screenshot',str(image),*extra]
    environment=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=str(private/('preferences-'+name)))
    result=subprocess.run(command,env=environment,capture_output=True,text=True,timeout=900)
    (artifacts/(name+'.log')).write_text(result.stdout+result.stderr)
    assert result.returncode==0,f'{name}: GUI failed; see retained log'
    final_size=size
    for event in events:
        if event.startswith('resize '):final_size=tuple(map(int,event.split()[1:]))
    assert struct.unpack_from('<ii',image.read_bytes(),18)==final_size
    assert 'font=Inter' in result.stdout
    if loaded:
        assert 'version=4' in result.stdout
        expected='bitcoin-message-ecdsa-v1' if profile=='bitcoin-message-p2pkh' else 'bip322-ecdsa-v1'
        assert 'profile='+expected in result.stdout
    records.append(dict(name=name,command=command,exit=result.returncode,width=final_size[0],height=final_size[1],initialFontScale=scale,image=str(image)))
    return result.stdout

for profile in ['bitcoin-message-p2pkh','bip322-p2wpkh']:
    root=private/profile;fixtures(root,cli,profile)
    for size in layouts:
        for scale in ['1','2']:
            run(profile,f'{profile}-review-{size[0]}-{scale}',size,scale,['pagedown']*3)
            log=run(profile,f'{profile}-receipt-focus-{size[0]}-{scale}',size,scale,['tab']*7)
            assert 'focus=312' in log,'keyboard must reach private receipt input'
    for error in ['wrong-profile','v3']:
        log=run(profile,f'{profile}-{error}-receipt',events=['tab']*8+['enter']+['wait']*30,
                extra=['--receipt-input',str(root/(error+'.qpa'))])
        assert 'generated=0' in log
    for error in ['v3','unknown-profile','future-profile']:
        log=run(profile,f'{profile}-{error}-request',extra=['--request',str(root/(error+'.qpr'))],loaded=False)
        assert 'GUI request: loaded=0' in log and 'generated=0' in log
    public=artifacts/(profile+'.qpf');assert not public.exists()
    captures=[];events=['tab']*8+['enter','await-proof','control 11','destination '+str(public),'control 307','await-save']
    for size in layouts:
        for scale in ['1','2']:
            image=artifacts/f'{profile}-verified-{size[0]}-{scale}.bmp';captures.append((image,size))
            events+=['resize '+str(size[0])+' '+str(size[1]),'control 1']+['tab']*(9 if scale=='2' else 6)+['enter','control 4','home','capture '+str(image)]
    log=run(profile,profile+'-prove-save',events=events)
    assert 'generated=1' in log and 'GUI save: retained=1' in log
    assert public.is_file() and public.stat().st_mode&0o777==0o600
    assert public.read_bytes()[:5]==b'QPE1\x04'
    for image,size in captures:assert struct.unpack_from('<ii',image.read_bytes(),18)==size
    actual=re.findall(r'GUI capture layout: \d+ fontIndex=(\d) logical=(\d+)x(\d+)',log)
    assert actual==[('0','400','760'),('3','400','760'),('0','1100','900'),('3','1100','900')],actual
    verified=subprocess.run([str(driver),str(root),str(public)],capture_output=True,text=True,timeout=300)
    (artifacts/(profile+'-independent-verify.log')).write_text(verified.stdout+verified.stderr)
    assert verified.returncode==0,'saved GUI proof failed independent exact-request verification'
    request=artifacts/(profile+'.qpr');request.write_bytes((root/'request.qpr').read_bytes())
    proofs.append(dict(profile=profile,request=str(request),proof=str(public),requestSha256=hashlib.sha256(request.read_bytes()).hexdigest(),
                       proofSha256=hashlib.sha256(public.read_bytes()).hexdigest(),independentVerificationExit=verified.returncode,
                       captures=[dict(image=str(p),width=s[0],height=s[1]) for p,s in captures]))

profile='bitcoin-message-p2pkh'
log=run(profile,'receipt-revision-cancel',events=['tab']*8+['enter']+['wait']*3+['backtab','text x']+['wait']*5)
assert 'generated=0' in log and 'GUI wallet: prompt=0' in log
assert 'GUI proof stage:' in log and int(re.search(r'GUI probe: .*revision=(\d+)',log)[1])>1,'input revision must invalidate an entered proof job'
(artifacts/'summary.json').write_text(json.dumps(dict(captures=records,proofs=proofs,proofsVerified=2,ownedProcessesRemaining=0,
    sourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    renderer='SDL dummy/software; actual application controls and Inter fonts; physical display unqualified'),indent=2)+'\n')
print(f'GUI PoSC: {len(records)} native runs, 8 verified-result captures; 2 actual profile proofs saved and independently verified; no wallet credentials')
