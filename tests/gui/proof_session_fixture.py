"""Synthetic proof-worker contracts and three serialized real native proof calls."""
import json
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from wallet_session_fixture import Server, line

SCENARIOS = ('success','generation-failure','generation-exception','expires-proof','cancel-before','cancel-unlock','cancel-prove-entry',
             'cancel-after-validation','cancel-completion','cancel-proof',
             'throw-proof','close-proof','worker-cancel','worker-close',
             'native-success','native-cancel','native-worker-late')


def main():
    executable, artifacts = map(lambda p: Path(p).resolve(),sys.argv[1:3])
    artifacts.mkdir(parents=True,exist_ok=True)
    server = Server(); thread = threading.Thread(target=server.serve_forever); thread.start()
    records = []; process = None
    try:
        with tempfile.TemporaryDirectory(prefix='quietproof-proof-session-') as directory:
            cookie = Path(directory)/'.cookie'
            cookie.write_text('__cookie__:'+''.join(chr(97+i) for i in range(12))); cookie.chmod(0o600)
            selected = tuple(x for x in SCENARIOS if not ('--fast' in sys.argv[3:] and x.startswith('native-')))
            for scenario in selected:
                server.idle(); server.scenario = scenario if scenario.startswith('worker-') else 'locked'
                server.calls=[]; server.states=0; server.unlocks=0; server.violation=None
                server.entered.clear(); server.release.clear()
                held = scenario in ('cancel-proof','throw-proof','close-proof','native-cancel','worker-cancel','worker-close')
                try:
                    command = [str(executable),f'http://127.0.0.1:{server.server_port}/',str(cookie),scenario,str(artifacts/'native.qpf')]
                    process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    if held:
                        if scenario == 'native-cancel':
                            assert select.select([process.stdout],[],[],120)[0], 'native commitment callback was not entered'
                        assert line(process) == ('started' if scenario.startswith('worker-') else 'proof-held'), 'held proof precondition absent'
                        if scenario.startswith('worker-'):
                            assert server.entered.wait(4), 'RPC hold precondition absent'
                        else:
                            assert [x['method'] for x in server.calls][-1] == 'walletlock', 'proof began before captured wallet relock'
                        process.stdin.write('x'); process.stdin.flush()
                        assert line(process) == 'invalidated', 'invalidation not observed'
                        assert process.poll() is None, 'held operation settled before release'
                        server.release.set()
                        process.stdin.write('x'); process.stdin.flush()
                    stdout,stderr = process.communicate(timeout=240 if scenario.startswith('native-') else 10)
                    code = process.returncode; process = None
                    count = re.search(r'Proof session: (\d+) checks passed; held=0 in-flight=0',stdout)
                    assert code == 0 and count, f'{scenario}: driver failed'
                    server.idle(); assert not server.violation, 'RPC fixture assertion failed'
                    methods = [x['method'] for x in server.calls]
                    assert methods.count('walletpassphrase') <= 1, 'unlock silently repeated'
                    if scenario not in ('cancel-before','cancel-unlock'): assert methods[-1] == 'walletlock', 'wallet cleanup absent'
                    else: assert not set(methods) & {'walletpassphrase','exportaddresskey','walletlock'}, 'canceled pre-unlock operation accessed key'
                    if scenario.startswith('worker-'): assert 'exportaddresskey' not in methods, 'canceled worker exported key'
                    records.append({'scenario':scenario,'exit':code,'checks':int(count[1]),
                                    'native_prover':scenario.startswith('native-'),'held_precondition':held,
                                    'released_before_join':held,'remaining_operations':server.active,'calls':server.calls})
                finally:
                    server.release.set()
                    if process:
                        try: process.communicate(input='xx',timeout=240)
                        except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=3)
                        process = None
                    server.idle()
    finally:
        server.release.set(); server.idle(); server.shutdown(); server.server_close(); thread.join(timeout=4)
        assert not thread.is_alive() and server.active == 0, 'proof harness cleanup incomplete'
    summary = {'scenarios':records,'checks':sum(x['checks'] for x in records),'held_operations':0,'in_flight_operations':0,
               'native_omitted_for_fast_mode':3 if '--fast' in sys.argv[3:] else 0}
    (artifacts/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(f"Proof sessions: {len(records)} scenarios, {summary['checks']} checks passed; held=0 in-flight=0")


if __name__ == '__main__': main()
