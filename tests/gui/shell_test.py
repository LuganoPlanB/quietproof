"""Exercise the native shell layout, keyboard paths and display-only storage."""
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
checks = 0

with tempfile.TemporaryDirectory(prefix='quietproof-display-') as directory:
    environment = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
                       XDG_DATA_HOME=directory)

    def run(name, args=(), events=()):
        global checks
        script = artifacts / (name + '.events')
        script.write_text('\n'.join(events) + ('\n' if events else ''))
        image = artifacts / (name + '.bmp')
        result = subprocess.run([str(executable), '--smoke-test', '--screenshot', str(image),
                                 '--test-events', str(script), *args], env=environment,
                                capture_output=True, text=True, timeout=10)
        (artifacts / (name + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (name, result.stderr)
        match = re.search(r'view=(\w+) theme=(\w+) fontIndex=(\d+) focus=(\d+) scrollY=(\d+) '
                          r'pixels=(\d+)x(\d+) logical=(\d+)x(\d+)', result.stdout)
        assert match, (name, result.stdout)
        state = dict(zip(('view', 'theme', 'font', 'focus', 'scroll', 'pw', 'ph', 'w', 'h'), match.groups()))
        state.update({key: int(state[key]) for key in ('font', 'focus', 'scroll', 'pw', 'ph', 'w', 'h')})
        controls = {int(row[0]): tuple(map(float, row[1:])) for row in
                    re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',
                               result.stdout, re.M)}
        data = image.read_bytes()
        assert struct.unpack_from('<ii', data, 18) == (state['pw'], state['ph'])
        for identifier in (1, 2, 3, 4, 11):
            x, y, width, height = controls[identifier]
            assert 0 <= x < x + width <= state['w'] and 0 <= y < y + height <= state['h'], (name, identifier, controls)
        checks += 1
        return state, controls, data

    for theme, size, scale, density, settings in itertools.product(
            ('light', 'dark'), ((400, 640), (480, 720), (600, 900)),
            ('1', '1.25', '1.5'), (1, 2), (False, True)):
        width, height = size
        name = f'{theme}-{width}x{height}-{scale}-{density}x-{"settings" if settings else "shell"}'
        state, controls, data = run(name, ['--theme', theme, '--width', str(width), '--height', str(height),
                                   '--font-scale', scale, '--pixel-scale', str(density)] +
                                   (['--settings'] if settings else []))
        assert (state['pw'], state['ph']) == (width * density, height * density)
        assert state['font'] == ('1', '1.25', '1.5').index(scale)
        assert state['theme'] == theme
        offset = struct.unpack_from('<I', data, 10)[0]
        # The bottom-left pixel is the exact official canvas token (BGRA).
        expected = bytes((250, 254, 255)) if theme == 'light' else bytes((23, 23, 23))
        assert data[offset:offset + 3] == expected, name
        if settings:
            for identifier in range(5, 10):
                assert controls[identifier][1] >= 160 or height > 640

    compact = ['--width', '400', '--height', '640', '--font-scale', '1.5']
    assert run('node', compact, ['tab', 'enter'])[0]['view'] == 'node'
    assert run('result', compact, ['tab', 'tab', 'space'])[0]['view'] == 'result'
    state, _, _ = run('theme-change', ['--settings', '--theme', 'light'], ['tab', 'enter'])
    assert state['theme'] == 'dark' and state['focus'] == 6
    state, _, _ = run('font-change', ['--settings'], ['tab', 'tab', 'tab', 'tab', 'enter'])
    assert state['font'] == 2
    state, _, _ = run('persisted')
    assert state['theme'] == 'dark' and state['font'] == 2
    preferences = list(Path(directory).rglob('display.conf'))
    assert len(preferences) == 1
    assert preferences[0].read_text() == 'theme=dark\nfont=2\n'
    assert preferences[0].stat().st_mode & 0o777 == 0o600
    preferences[0].write_text('theme=dark\nfont=99\nsecret=not-a-preference\n')
    assert run('invalid-preferences')[0]['font'] == 0
    preferences[0].write_text('x' * 129)
    assert run('oversize-preferences')[0]['theme'] == 'light'
    state, _, _ = run('guide-end', ['--width', '400', '--height', '640', '--font-scale', '1.5'],
                      ['backtab', 'backtab', 'backtab', 'enter', 'end'])
    assert state['scroll'] > 0
    state, controls, _ = run('guide-focus', ['--width', '400', '--height', '640', '--font-scale', '1.5'],
                             ['backtab', 'backtab', 'backtab', 'enter', 'end', 'backtab', 'tab'])
    assert state['focus'] == 10 and 160 <= controls[10][1] <= 440
    state, controls, _ = run('settings-focus', ['--settings', '--width', '400', '--height', '640',
                                              '--font-scale', '1.5'], ['end', 'tab'])
    assert state['focus'] == 6 and 160 <= controls[6][1] <= 440
    assert run('settings-escape', ['--settings'], ['escape'])[0]['view'] == 'request'
    assert run('settings-done', ['--settings'], ['backtab'] * 5 + ['enter'])[0]['view'] == 'request'
    # SDL's event filter converts physical window coordinates to logical positions.
    for density in (1, 2):
        state, _, _ = run(f'pointer-{density}x', ['--pixel-scale', str(density)],
                          [f'click {400 * density} {35 * density}'])
        assert state['view'] == 'settings', (density, state)
        state, _, _ = run(f'control-pointer-{density}x', ['--pixel-scale', str(density)],
                          ['control 1', 'control 5', 'control 7', 'control 11'])
        assert (state['view'], state['theme'], state['font']) == ('request', 'light', 0), (density, state)

print(f'GUI shell: {checks} rendered checks passed; 72 matrix captures, keyboard, scrolling, '
      'HiDPI pointer coordinates and nonsecret preferences')
