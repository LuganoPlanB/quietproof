"""Native private-input screenshots and lifecycle checks; no plaintext test data on disk."""
import itertools
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from wallet_session_fixture import Server


def main():
    executable, driver, artifacts = map(lambda p: Path(p).resolve(), sys.argv[1:4])
    artifacts.mkdir(parents=True,exist_ok=True)
    server = Server()
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    captures, records = 0, []
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='quietproof-private-ui-') as directory:
            root = Path(directory)
            preferences = root/'Plan-B'/'quietproof'
            preferences.mkdir(parents=True)
            cookie = root/'.cookie'
            cookie.write_text('__cookie__:'+''.join(chr(97+i) for i in range(12)))
            cookie.chmod(0o600)
            fields = ['127.0.0.1',str(server.server_port),'',str(cookie),'','500','500']
            configuration = 'quietproof-node=1\n'+''.join(f'{i} {json.dumps(value)}\n' for i,value in enumerate(fields))
            (preferences/'node.conf').write_text(configuration)
            (preferences/'node.conf').chmod(0o600)
            request = root/'wallet.qpr'
            subprocess.run([str(driver),'--write-request',str(request)],check=True,capture_output=True,timeout=5)
            replacement = root/'replacement.qpr'
            subprocess.run([str(driver),'--write-replacement',str(replacement)],check=True,capture_output=True,timeout=5)
            assert request.read_bytes() != replacement.read_bytes(), 'replacement request precondition absent'
            environment = dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=directory,HOME=directory)
            # Only public control commands reach disk. The synthetic input event
            # is generated in a short-lived SDL buffer inside the test process.
            opening = ['control 3','control 11']+['wait']*12+['control 2','control 304']+['wait']*12
            def run(name,events,theme='light',size=(480,720),scale='1',capture=False):
                server.idle(); server.calls=[]; server.states=0; server.unlocks=0; server.violation=None
                server.entered.clear(); server.release.clear()
                script = artifacts/(name+'.events'); script.write_text('\n'.join(events)+'\n')
                command = [str(executable),'--smoke-test','--theme',theme,'--font-scale',scale,
                           '--width',str(size[0]),'--height',str(size[1]),'--request',str(request),'--test-events',str(script)]
                if capture: command += ['--screenshot',str(artifacts/(name+'.bmp'))]
                result = subprocess.run(command,env=environment,capture_output=True,text=True,timeout=15)
                marker = ''.join(chr(65+i) for i in range(12))
                cookie_marker = ''.join(chr(97+i) for i in range(12))
                diagnostic = result.stdout+result.stderr
                for private in (marker,cookie_marker,'server-private-diagnostic'):
                    diagnostic = diagnostic.replace(private,'[redacted fixture data]')
                (artifacts/(name+'.log')).write_text(diagnostic)
                assert result.returncode == 0, f'{name}: native GUI failed'
                assert 'server-private-diagnostic' not in result.stdout+result.stderr, 'server diagnostics escaped'
                # Runtime-generated fixture input must never enter logs or saved settings.
                assert marker not in result.stdout+result.stderr and marker not in (preferences/'node.conf').read_text()
                assert (preferences/'node.conf').read_text() == configuration, 'private flow changed settings'
                server.idle(); assert not server.violation, f'{name}: transcript violation'
                state = re.search(r'GUI wallet: prompt=(\d) masked=(\d) cleared=(\d) busy=(\d)',result.stdout)
                assert state and state[3]=='1', f'{name}: owned input not cleared on shutdown'
                record={'name':name,'exit':result.returncode,'prompt':int(state[1]),'masked':int(state[2]),
                        'cleared':int(state[3]),'busy':int(state[4]),'calls':server.calls,'remaining_operations':server.active}
                navigation=re.search(r'GUI wallet: .* focus=(\d+) scroll=(\d+)',result.stdout)
                assert navigation, 'private navigation metadata absent'
                record.update(focus=int(navigation[1]),scroll=int(navigation[2]))
                context=re.search(r'GUI wallet context: transient=(\d) checked=(\d) warning=(\d)',result.stdout)
                assert context, 'wallet context metadata absent'
                record.update(transient_status=int(context[1]),checked=int(context[2]),warning=int(context[3]))
                if capture:
                    controls={int(row[0]):tuple(map(float,row[1:])) for row in re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',result.stdout,re.M)}
                    for control in (301,302,303):
                        x,y,w,h=controls[control]
                        assert 0 <= x < x+w <= size[0] and 0 <= y < y+h <= size[1], f'{name}: private action clipped'
                    record.update(theme=theme,width=size[0],height=size[1],font_scale=scale,screenshot=str(artifacts/(name+'.bmp')))
                records.append(record)
                return record
            for theme,size,scale in itertools.product(('light','dark'),((400,640),(480,720)),('1','1.5')):
                server.scenario='locked'
                name=f'masked-{theme}-{size[0]}x{size[1]}-{scale}'
                value=run(name,opening+['private-synthetic','copy','cut','paste','undo','redo','wait'],theme,size,scale,True)
                assert value['prompt']==1 and value['masked']==1 and value['busy']==0, f'{name}: missing masked dialog'
                assert not set(x['method'] for x in value['calls']) & {'walletpassphrase','exportaddresskey','walletlock'}, 'dialog typing accessed key'
                captures+=1
            server.scenario='locked'
            value=run('cancel',opening+['private-synthetic','escape','wait'])
            assert value['prompt']==0 and value['masked']==0
            assert value['transient_status']==1 and value['checked']==0, 'explicit cancel feedback missing'
            assert 'walletpassphrase' not in [x['method'] for x in value['calls']], 'cancel submitted a password'
            value=run('keyboard',opening+['private-synthetic','tab','backtab','pagedown','wait'],size=(400,640),scale='1.5',capture=True)
            assert value['prompt']==1 and value['masked']==1 and value['focus']==0 and value['scroll']>0, 'keyboard focus/scroll failed'
            server.scenario='retry'
            value=run('retry-empty',opening+['private-synthetic','enter']+['wait']*15)
            assert value['prompt']==1 and value['masked']==0, 'wrong password remained cached'
            assert value['transient_status']==1 and value['checked']==0, 'explicit retry feedback missing'
            assert [x['method'] for x in value['calls']].count('walletpassphrase')==1, 'wrong password silently retried'
            server.scenario='retry'
            value=run('retry-explicit',opening+['private-synthetic','enter']+['wait']*15+['private-synthetic','enter']+['wait']*15)
            methods=[x['method'] for x in value['calls']]
            assert value['prompt']==0 and value['masked']==0 and methods.count('walletpassphrase')==2 and methods[-1]=='walletlock', 'explicit retry did not clean up'
            server.scenario='locked'
            value=run('replacement',opening+['private-synthetic','drop '+str(request)]+['wait']*3)
            assert value['prompt']==0 and value['masked']==0 and 'walletpassphrase' not in [x['method'] for x in value['calls']], 'request replacement retained input'
            for state in ('unlocked','unencrypted'):
                server.scenario=state
                value=run(state,opening+['wait']*8)
                methods=[x['method'] for x in value['calls']]
                assert value['prompt']==0 and 'exportaddresskey' in methods and 'walletpassphrase' not in methods and 'walletlock' not in methods, 'preexisting state changed'
                assert value['transient_status']==1 and value['checked']==1, 'successful prior-session precondition absent'
            server.scenario='unlocked'
            value=run('status-request-replaced',opening+['wait']*8+['drop '+str(replacement)]+['wait']*3)
            assert 'exportaddresskey' in [x['method'] for x in value['calls']], 'successful key access precondition absent'
            assert value['transient_status']==0 and value['checked']==0, 'old success describes replaced request'
            value=run('status-settings-replaced',opening+['wait']*8+['control 3','tab','tab','enter','tab','text 1']+['wait']*3)
            assert 'exportaddresskey' in [x['method'] for x in value['calls']], 'successful key access precondition absent'
            assert value['transient_status']==0 and value['checked']==0, 'old success describes changed settings'
            server.scenario='relock-failure'
            value=run('status-warning-preserved',opening+['private-synthetic','enter']+['wait']*15+['drop '+str(replacement)]+['wait']*3)
            assert [x['method'] for x in value['calls']].count('walletlock')==1, 'cleanup warning precondition absent'
            assert value['transient_status']==0 and value['checked']==0 and value['warning']==1, 'captured-wallet cleanup warning lost on replacement'
            # Close while an unlock response is held. Observe that SDL reaches
            # its responsive closing state before releasing the server gate.
            server.idle(); server.scenario='close'; server.calls=[]; server.states=0; server.unlocks=0; server.violation=None
            server.entered.clear(); server.release.clear()
            script=artifacts/'close-held.events'
            script.write_text('\n'.join(opening+['private-synthetic','enter']+['wait']*6+['quit'])+'\n')
            process=subprocess.Popen([str(executable),'--smoke-test','--request',str(request),'--test-events',str(script)],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert server.entered.wait(5), 'held UI unlock precondition absent'
            captured=b''; deadline=time.monotonic()+5
            while b'GUI wallet close: waiting for bounded cleanup' not in captured and time.monotonic()<deadline:
                if select.select([process.stdout],[],[],.1)[0]: captured+=os.read(process.stdout.fileno(),4096)
            assert b'GUI wallet close: waiting for bounded cleanup' in captured, 'SDL did not process close while RPC held'
            assert process.poll() is None and not server.release.is_set(), 'held close settled prematurely'
            server.release.set()
            stdout,stderr=process.communicate(timeout=8)
            assert process.returncode==0, 'held close failed'
            process=None; server.idle(); assert not server.violation
            methods=[x['method'] for x in server.calls]
            assert methods[-1]=='walletlock' and 'exportaddresskey' not in methods, 'held close failed cleanup'
            records.append({'name':'close-held','exit':0,'held_precondition':True,'responsive_close_observed':True,'remaining_operations':server.active,'calls':server.calls})
    finally:
        server.release.set()
        if process:
            try: process.communicate(timeout=8)
            except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=2)
        server.idle(); server.shutdown(); server.server_close(); thread.join(timeout=4)
        assert not thread.is_alive() and server.active==0, 'UI fixture cleanup incomplete'
    (artifacts/'summary.json').write_text(json.dumps({'captures':captures,'records':records,'held_operations':0,'in_flight_operations':0},indent=2)+'\n')
    print(f'Private UI: {captures} native masked captures, {len(records)} scenarios passed; held=0 in-flight=0')


if __name__ == '__main__':
    main()
