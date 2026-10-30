"""Native Node settings matrix, override persistence, reset and keyboard reachability."""
import itertools
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

executable = Path(sys.argv[1]).resolve()
artifacts = Path(sys.argv[2]).resolve()
artifacts.mkdir(parents=True, exist_ok=True)
fixtures = Path(sys.argv[3]).resolve()
checks = 0

with tempfile.TemporaryDirectory(prefix='quietproof-node-ui-') as directory:
    env = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
               XDG_DATA_HOME=directory, HOME=directory)
    def run(name, args=(), events=()):
        global checks
        script = artifacts / (name + '.events')
        script.write_text('\n'.join(events) + '\n')
        image = artifacts / (name + '.bmp')
        result = subprocess.run([str(executable), '--smoke-test', '--screenshot', str(image),
                                 '--test-events', str(script), *args], env=env,
                                capture_output=True, text=True, timeout=15)
        (artifacts / (name + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (name, result.stderr)
        match = re.search(r'view=(\w+) theme=(\w+) fontIndex=(\d+) focus=(\d+) scrollY=(\d+) '
                          r'pixels=(\d+)x(\d+) logical=(\d+)x(\d+)', result.stdout)
        assert match and match[1] == 'node', (name, result.stdout)
        assert 'configured=1' in result.stdout, (name,result.stdout)
        controls = {int(row[0]): tuple(map(float,row[1:])) for row in
                    re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$', result.stdout,re.M)}
        width, height = int(match[8]), int(match[9])
        assert struct.unpack_from('<ii',image.read_bytes(),18) == (width,height)
        for control in (1,2,3,4,11):
            x,y,w,h = controls[control]
            assert 0 <= x < x+w <= width and 0 <= y < y+h <= height, (name,control)
        checks += 1
        return int(match[4]), controls

    node = ['tab','enter']
    advanced = node + ['tab']*3 + ['enter']
    for theme, size, scale in itertools.product(('light','dark'),((400,640),(480,720)),('1','1.5')):
        args = ['--theme',theme,'--width',str(size[0]),'--height',str(size[1]),'--font-scale',scale]
        name = f'{theme}-{size[0]}x{size[1]}-{scale}'
        run(name+'-overview',args,node)
        focus,controls = run(name+'-advanced',args,advanced+['tab'])
        assert focus == 278 and 140 <= controls[278][1] and controls[278][1]+controls[278][3] < controls[11][1]-30, (name,focus,controls[278])
        focus,controls = run(name+'-reset',args,advanced+['tab']*9)
        assert focus == 276 and 140 <= controls[276][1] and controls[276][1]+controls[276][3] < controls[11][1]-30, (name,focus,controls[276])

    # Blank inherited fields can be edited by keyboard; Tab leaves the editor,
    # reaches Save, and the private nonsecret file round-trips on next launch.
    focus,_ = run('save-port',events=advanced+['tab']*2+['text 19000']+['tab']*6+['enter'])
    assert focus == 275
    paths = list(Path(directory).rglob('node.conf'))
    assert len(paths) == 1 and paths[0].stat().st_mode & 0o777 == 0o600
    assert '1 "19000"' in paths[0].read_text(), paths[0].read_text()
    run('persisted-override',events=node)
    run('reset-defaults',events=advanced+['tab']*9+['enter'])
    assert paths[0].read_text() == 'quietproof-node=1\n'+''.join(f'{i} ""\n' for i in range(7))
    paths[0].write_text('password=synthetic-unrecognized-field\n')
    run('corrupt-config',events=node)
    run('test-network',events=node+['tab']*2+['enter'])
    assert 'network=testnet3' in (artifacts/'test-network.log').read_text()
    run('request-network',['--request',str(fixtures/'review-v2.qpr')],node)
    assert 'network=regtest' in (artifacts/'request-network.log').read_text()

print(f'GUI Node settings: {checks} rendered checks passed; 24 matrix captures, keyboard editing, save/reset and corrupt config')
