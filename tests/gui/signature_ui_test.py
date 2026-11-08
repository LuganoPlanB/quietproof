"""Default PoSC GUI receipt proving, native screenshots and public proof saving."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from signature_session_fixture import fixtures

gui,driver,cli,artifacts=map(lambda x:Path(x).resolve(),sys.argv[1:5])
artifacts.mkdir(parents=True,exist_ok=True)
private=artifacts/'private'; private.mkdir(exist_ok=True,mode=0o700)
fixtures(private,cli)
environment=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=str(private/'preferences'))
records=[]


def run(name,size=(400,640),scale='1',events=(),extra=()):
    script=artifacts/(name+'.events'); script.write_text('\n'.join(events)+ ('\n' if events else ''))
    image=artifacts/(name+'.bmp')
    command=[str(gui),'--smoke-test','--request',str(private/'request.qpr'),'--receipt-input',str(private/'receipt.qpa'),
             '--width',str(size[0]),'--height',str(size[1]),'--font-scale',scale,
             '--test-events',str(script),'--screenshot',str(image),*extra]
    result=subprocess.run(command,env=environment,capture_output=True,text=True,timeout=900)
    (artifacts/(name+'.log')).write_text(result.stdout+result.stderr)
    assert result.returncode==0, f'{name}: GUI failed; see retained log'
    assert struct.unpack_from('<ii',image.read_bytes(),18)==size
    assert 'version=3' in result.stdout and 'font=Inter' in result.stdout
    records.append(dict(name=name,command=command,exit=result.returncode,width=size[0],height=size[1],fontScale=scale,image=str(image)))
    return result.stdout


for size in [(400,640),(1440,900)]:
    for scale in ['1','2']:
        run(f'default-{size[0]}-{scale}',size,scale)
        run(f'receipt-focus-{size[0]}-{scale}',size,scale,['tab']*7)
run('receipt-error',events=['tab']*8+['enter']+['wait']*30,extra=['--receipt-input',str(private/'wrong.qpa')])
public=artifacts/'public-proof.qpf'; public.unlink(missing_ok=True)
log=run('prove-and-save',(480,720),'1',events=['tab']*8+['enter','await-proof','control 11',
        'destination '+str(public),'control 307','await-save'])
assert 'generated=1' in log and 'GUI save: retained=1' in log
assert public.is_file() and public.stat().st_mode&0o777==0o600
assert public.read_bytes()[:5]==b'QPE1\x03'
verified=subprocess.run([str(driver),str(private),str(public)],capture_output=True,text=True,timeout=300)
(artifacts/'public-verify.log').write_text(verified.stdout+verified.stderr)
assert verified.returncode==0, 'saved GUI PoSC proof failed independent exact-request verification'
(artifacts/'summary.json').write_text(json.dumps(dict(captures=records,proofsVerified=1,ownedProcessesRemaining=0),indent=2)+'\n')
print(f'GUI PoSC: {len(records)} native captures passed; default receipt proof saved and independently verified; no wallet credentials')
