"""Real SDL screenshots against the synthetic nonsecret RPC fixture."""
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from node_probe_fixture import ProbeServer

executable = Path(sys.argv[1]).resolve()
fixtures = Path(sys.argv[2]).resolve()
artifacts = Path(sys.argv[3]).resolve()
artifacts.mkdir(parents=True, exist_ok=True)
captures = 0
server = ProbeServer()
thread = threading.Thread(target=server.serve_forever)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix='quietproof-probe-ui-') as directory:
        root = Path(directory)
        preferences = root/'Plan-B'/'quietproof'
        preferences.mkdir(parents=True)
        cookie = root/'.cookie'
        cookie.write_text('__cookie__:synthetic-cookie\n')
        cookie.chmod(0o600)
        fields = ['127.0.0.1', str(server.server_port), '', str(cookie), '', '250', '250']
        (preferences/'node.conf').write_text('quietproof-node=1\n'+''.join(f'{i} {json.dumps(value)}\n' for i,value in enumerate(fields)))
        (preferences/'node.conf').chmod(0o600)
        environment = dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',
                           XDG_DATA_HOME=directory,HOME=directory)
        server.script = '76a914'+'47'*20+'88ac'  # Existing synthetic mixed-script request.
        for scenario, theme, scale in itertools.product(
                ('success','unsupported','unauthorized','multiple','multiple-selection','watch-only','timeout'),
                ('light','dark'),('1','1.5')):
            server.idle()
            server.scenario,server.calls = ('multiple' if scenario == 'multiple-selection' else scenario),[]
            server.violation = None
            name = f'{scenario}-{theme}-{scale}'
            script = artifacts/(name+'.events')
            # Node > Test connection; the wait events leave SDL processing live.
            events = ['tab','enter']+['backtab']*3+['enter']+['wait']*25
            if scenario == 'multiple-selection':
                events += ['tab']*6+['enter']+['wait']*16
            script.write_text('\n'.join(events)+'\n')
            result = subprocess.run([str(executable),'--smoke-test','--theme',theme,'--font-scale',scale,
                                     '--request',str(fixtures/'review-v2.qpr'),
                                     '--test-events',str(script),'--screenshot',str(artifacts/(name+'.bmp'))],
                                    env=environment,capture_output=True,text=True,timeout=15)
            (artifacts/(name+'.log')).write_text(result.stdout+result.stderr)
            assert result.returncode == 0, (name,result.stderr)
            status = re.search(r'GUI probe: busy=(\d+) report=(\d+) revision=(\d+) authenticated=(\d+) complete=(\d+) selected=(\d+) error=(\d+)',result.stdout)
            assert status and status[1] == '0' and status[2] == '1', (name,result.stdout)
            assert status[6] == ('1' if scenario in ('success','multiple-selection') else '0'), (name,status.groups())
            assert 'synthetic-cookie' not in result.stdout+result.stderr
            assert 'server-private-diagnostic' not in result.stdout+result.stderr
            assert 'prove=disabled' in result.stdout
            server.idle()
            assert server.violation is None, (name,server.violation)
            controls = {int(row[0]):tuple(map(float,row[1:])) for row in re.findall(
                r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',result.stdout,re.M)}
            x,y,w,h = controls[11]
            assert 0 <= x < x+w <= 480 and 0 <= y < y+h <= 720
            (artifacts/(name+'.json')).write_text(json.dumps(server.calls,indent=2))
            captures += 1
        # UI changes clear an already accepted report. The held-worker C++ test
        # separately proves a late result cannot restore the invalidated state.
        for change in ('settings','request','network'):
            server.idle()
            server.scenario,server.calls = 'success',[]
            server.violation = None
            args = [] if change == 'network' else ['--request',str(fixtures/'review-v2.qpr')]
            events = ['tab','enter']+['backtab']*3+['enter']+['wait']*25
            if change == 'settings':
                events += ['tab']*5+['enter']+['tab']*2+['text 1']
            elif change == 'request':
                events += ['drop '+str(fixtures/'review-v2.qpr')]
            else:
                events += ['tab']*5+['enter']
            script = artifacts/(change+'-invalidate.events')
            script.write_text('\n'.join(events)+'\n')
            result = subprocess.run([str(executable),'--smoke-test','--test-events',str(script),*args],
                                    env=environment,capture_output=True,text=True,timeout=15)
            (artifacts/(change+'-invalidate.log')).write_text(result.stdout+result.stderr)
            assert result.returncode == 0 and re.search(r'GUI probe: busy=0 report=0',result.stdout), (change,result.stdout,result.stderr)
            server.idle()
            assert server.violation is None
            assert server.calls, 'precondition: no probe ran before invalidation'
        server.scenario = 'success'
        script = artifacts/'advanced-test.events'
        events = ['tab','enter']+['tab']*2+['enter']+['backtab']*5+['enter']+['wait']*25
        script.write_text('\n'.join(events)+'\n')
        result = subprocess.run([str(executable),'--smoke-test','--request',str(fixtures/'review-v2.qpr'),
                                 '--test-events',str(script)],env=environment,capture_output=True,text=True,timeout=15)
        (artifacts/'advanced-test.log').write_text(result.stdout+result.stderr)
        assert result.returncode == 0 and 'advanced=0' in result.stdout and re.search(r'GUI probe: busy=0 report=1',result.stdout), result.stdout
        server.idle()
        assert server.violation is None
finally:
    server.release.set()
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)
    assert not thread.is_alive() and server.active == 0, 'UI fixture cleanup incomplete'
print(f'GUI probe: {captures} native status/error captures passed; both themes at 480x720, 100/150 percent; no secrets accessed; held=0 in-flight=0')
