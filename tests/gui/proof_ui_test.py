"""Native stage/cancellation captures with owned, released synthetic RPC gates."""
import itertools
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from wallet_session_fixture import Server


def main():
    executable, driver, artifacts = map(lambda p: Path(p).resolve(),sys.argv[1:4])
    artifacts.mkdir(parents=True,exist_ok=True)
    server = Server(); thread = threading.Thread(target=server.serve_forever); thread.start()
    process = None; records = []
    try:
        with tempfile.TemporaryDirectory(prefix='quietproof-proof-ui-') as directory:
            root=Path(directory); prefs=root/'Plan-B'/'quietproof'; prefs.mkdir(parents=True)
            cookie=root/'.cookie'; cookie.write_text('__cookie__:'+''.join(chr(97+i) for i in range(12))); cookie.chmod(0o600)
            fields=['127.0.0.1',str(server.server_port),'',str(cookie),'','3000','3000']
            configuration='quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(fields))
            (prefs/'node.conf').write_text(configuration); (prefs/'node.conf').chmod(0o600)
            request=root/'proof.qpr'; subprocess.run([str(driver),'--write-request',str(request)],check=True,capture_output=True,timeout=5)
            env=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=directory,HOME=directory)
            opening=['control 3','control 11']+['wait']*12+['control 2','control 304']+['wait']*12+['private-synthetic','enter']
            for cancel,theme,size,scale in itertools.product((False,True),('light','dark'),((400,640),(480,720)),('1','1.5')):
                server.idle(); server.scenario='close'; server.calls=[]; server.states=0; server.unlocks=0; server.violation=None
                server.entered.clear(); server.release.clear()
                name=f"{'cancel' if cancel else 'progress'}-{theme}-{size[0]}x{size[1]}-{scale}"
                script=artifacts/(name+'.events')
                # Mouse controls remain active during secret-owning work. The
                # screenshot is captured before smoke close asks the worker to settle.
                events=opening+['wait']*3+(['control 305'] if cancel else [])+['wait']*3
                script.write_text('\n'.join(events)+'\n')
                image=artifacts/(name+'.bmp')
                command=[str(executable),'--smoke-test','--theme',theme,'--width',str(size[0]),'--height',str(size[1]),
                         '--font-scale',scale,'--request',str(request),'--test-events',str(script),'--screenshot',str(image)]
                process=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    assert server.entered.wait(5), 'unlock hold was not entered before UI invalidation'
                    captured=b''; until=time.monotonic()+4
                    marker=b'GUI wallet close: waiting for bounded cleanup'
                    while marker not in captured and time.monotonic()<until:
                        if select.select([process.stdout],[],[],.1)[0]: captured+=os.read(process.stdout.fileno(),4096)
                    assert marker in captured and process.poll() is None, 'SDL failed responsive close while RPC held'
                    assert not server.release.is_set() and image.exists(), 'gate not held through screenshot'
                    server.release.set()  # Always release before waiting/joining.
                    stdout,stderr=process.communicate(timeout=10); stdout=captured+stdout
                    code=process.returncode; process=None
                    assert code==0 and not stderr, f'{name}: native rendering failure'
                    for private in (''.join(chr(65+i) for i in range(12)),''.join(chr(97+i) for i in range(12)),'server-private-diagnostic'):
                        assert private.encode() not in stdout+stderr, 'private data reached diagnostics'
                    log=stdout.decode(); (artifacts/(name+'.log')).write_text(log)
                    state=re.search(r'GUI proof: canceled=(\d) generated=(\d)',log)
                    assert state and int(state[1])==int(cancel) and state[2]=='0', 'Cancel interaction or partial-result state wrong'
                    server.idle(); assert not server.violation, 'RPC fixture failure'
                    methods=[x['method'] for x in server.calls]
                    assert methods[-1]=='walletlock' and 'exportaddresskey' not in methods, 'canceled export or captured-wallet cleanup wrong'
                    controls={int(r[0]):tuple(map(float,r[1:])) for r in re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',log,re.M)}
                    x,y,w,h=controls[305]
                    assert 0<=x<x+w<=size[0] and 0<=y<y+h<=size[1], 'Cancel action clipped'
                    assert y > size[1]-100, 'Cancel action must stay outside the scrolling details'
                    width,height=struct.unpack_from('<ii',image.read_bytes(),18)
                    assert (width,height)==size, 'native image dimensions wrong'
                    assert (prefs/'node.conf').read_text()==configuration, 'proof flow persisted private context'
                    records.append({'name':name,'exit':code,'theme':theme,'width':width,'height':height,'font_scale':scale,
                                    'cancel_clicked':cancel,'held_precondition':True,'responsive_close':True,
                                    'released_before_join':True,'remaining_operations':server.active,'calls':server.calls,'image':str(image)})
                finally:
                    server.release.set()
                    if process:
                        try: process.communicate(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=3)
                        process=None
                    server.idle()
    finally:
        server.release.set(); server.idle(); server.shutdown(); server.server_close(); thread.join(timeout=4)
        assert not thread.is_alive() and server.active==0, 'UI proof harness cleanup incomplete'
    (artifacts/'summary.json').write_text(json.dumps({'captures':len(records),'records':records,'held_operations':0,'in_flight_operations':0},indent=2)+'\n')
    print(f'Proof UI: {len(records)} native progress/cancel captures passed; held=0 in-flight=0')


if __name__=='__main__': main()
