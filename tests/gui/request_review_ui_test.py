"""Native request/claims matrix and literal untrusted-data/time-boundary checks."""
import itertools
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

executable, fixtures, artifacts = map(lambda p: Path(p).resolve(), sys.argv[1:4])
artifacts.mkdir(parents=True, exist_ok=True)
checks = 0
with tempfile.TemporaryDirectory(prefix='quietproof-review-') as temporary:
    environment = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_RENDER_DRIVER='software',
                       XDG_DATA_HOME=temporary, TZ='Pacific/Honolulu')

    def run(name, args=(), events=(), fixture='review-v2.qpr', now=1800000000, revision=1):
        global checks
        script = artifacts / (name + '.events')
        script.write_text('\n'.join(events))
        image = artifacts / (name + '.bmp')
        result = subprocess.run([str(executable), '--smoke-test', '--request', str(fixtures / fixture),
                                 '--test-now', str(now), '--test-events', str(script),
                                 '--screenshot', str(image), *map(str, args)],
                                capture_output=True, text=True, env=environment, timeout=10)
        (artifacts / (name + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (name, result.stderr)
        assert f'loaded=1 error=0 revision={revision} chooser=0 prove=disabled' in result.stdout, (name, result.stdout)
        match = re.search(r'GUI review: version=(\d+) window=([\w-]+) claimsExpanded=(\d) claimCount=(\d+)', result.stdout)
        assert match, (name, result.stdout)
        version, window, expanded, claims = match.groups()
        controls = {int(row[0]): tuple(map(float, row[1:])) for row in
                    re.findall(r'^control (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$', result.stdout, re.M)}
        width, height = struct.unpack_from('<ii', image.read_bytes(), 18)
        density = int(args[args.index('--pixel-scale')+1]) if '--pixel-scale' in args else 1
        for identifier in (1, 2, 3, 4, 11):
            x, y, w, h = controls[identifier]
            assert 0 <= x < x + w <= width / density and 0 <= y < y + h <= height / density, (name, identifier)
        checks += 1
        return (int(version), window, int(expanded), int(claims)), controls, result.stdout

    expand = ['tab'] * 5 + ['enter']
    for theme, size, scale, density, screen in itertools.product(
            ('light', 'dark'), ((400, 640), (480, 720), (600, 900)),
            ('1', '1.25', '1.5'), (1, 2), ('request', 'expanded')):
        width, height = size
        name = f'{theme}-{width}x{height}-{scale}-{density}x-{screen}'
        args = ['--theme', theme, '--width', width, '--height', height,
                '--font-scale', scale, '--pixel-scale', str(density)]
        state, _, _ = run(name, args, expand if screen == 'expanded' else [])
        assert state == (2, 'valid', screen == 'expanded', 2), (name, state)

    for theme in ('light', 'dark'):
        args = ['--theme', theme, '--width', 400, '--height', 640, '--font-scale', '1.5']
        baseline, expected, _ = run(f'{theme}-baseline', args)
        for fixture in ('long.qpr', 'directional.qpr', 'bridge.qpr'):
            state, controls, _ = run(f'{theme}-{fixture}', args, fixture=fixture)
            assert state == baseline
            assert controls.keys() == expected.keys(), (fixture, controls.keys())
            for identifier in (1, 2, 3, 4, 11, 272):
                assert controls[identifier] == expected[identifier], (fixture, identifier)
        for screen, events in (('summary-times', ['pagedown'] * 4),
                               ('summary-snapshot', ['pagedown'] * 8),
                               ('summary-block', ['pagedown'] * 10),
                               ('claims-script', expand + ['pagedown'] * 3),
                               ('claims-next', expand + ['pagedown'] * 6),
                               ('claims-tail', expand + ['end', 'pageup']),
                               ('many-claims-tail', expand + ['end', 'pageup'])):
            _, _, output = run(f'{theme}-{screen}', args, events,
                                fixture='many.qpr' if screen == 'many-claims-tail' else 'review-v2.qpr')
            assert re.search(r'scrollY=[1-9]\d*', output), (screen, output)
        state, controls, _ = run(f'{theme}-claims-focus', args,
                                 expand + ['end', 'backtab', 'tab'])
        assert state[2] == 1 and 150 <= controls[272][1] <= 450
        state, _, _ = run(f'{theme}-collapse', args, expand + ['enter'])
        assert state[2] == 0

    for now, window in ((-1, 'clock-unavailable'), (99, 'not-yet-valid'), (100, 'valid'),
                        (199, 'valid'), (200, 'expired'), (201, 'expired')):
        state, _, _ = run(f'boundary-{now}', fixture='boundaries.qpr', now=now)
        assert state[1] == window, (now, state)
    state, _, _ = run('v1', fixture='review-v1.qpr')
    assert state == (1, 'valid', 0, 2)
    state, _, _ = run('replace-resets-expanded', events=expand + ['drop ' + str(fixtures / 'review-v1.qpr')], revision=2)
    assert state == (1, 'valid', 0, 2)
    _, controls, output = run('chooser-then-node', events=['tab'] * 4 + ['enter'] + ['backtab'] * 3 + ['enter'])
    assert 'view=node' in output and 10 in controls

print(f'GUI request review: {checks} rendered checks passed; 72 full matrix captures, '
      'literal untrusted text, UTC boundaries, summary/claim scrolling and keyboard expansion')
