#!/usr/bin/env python3
"""Production readiness/UTXO transport, bounded timeouts and explicit Core32 smoke."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.records.append(request)
        method = request['method']
        block = '11' * 32
        if method == 'getblockchaininfo':
            result = dict(chain='regtest', blocks=200, bestblockhash=block,
                          time=10000, initialblockdownload=self.server.scenario == 'ibd')
        elif method == 'getchainstates':
            if self.server.scenario == 'timeout':
                time.sleep(0.25)
            result = dict(chainstates=[dict(blocks=100, bestblockhash='22'*32, validated=True),
                          dict(blocks=200, bestblockhash=block, validated=self.server.scenario != 'snapshot')])
        else:
            assert method == 'gettxout'
            assert request['params'] == ['11'*32, 3, True]
            result = (None if self.server.scenario in ('missing', 'mempool-spend') else
                      dict(bestblock=block, confirmations=99, value='EXACT_SATOSHI',
                           scriptPubKey=dict(hex='0014'+'aa'*20), coinbase=True))
        payload = dict(jsonrpc='2.0', id=request['id'], result=result)
        if method == 'getchainstates' and self.server.scenario == 'unsupported':
            payload = dict(jsonrpc='2.0', id=request['id'], error=dict(code=-32601, message='server-secret'))
        # Match Core's original decimal token; Python float formatting would
        # emit 1e-08, correctly rejected by the production money parser.
        data = json.dumps(payload).encode().replace(b'"EXACT_SATOSHI"', b'0.00000001')
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--core32', type=Path)
    parser.add_argument('--oracle', type=Path)
    args = parser.parse_args()
    subprocess.run([args.driver], timeout=20, check=True)
    count = 1
    with tempfile.TemporaryDirectory(prefix='signature-state-rpc-') as directory:
        cookie = Path(directory)/'cookie'
        cookie.write_text('fixture:private-cookie-must-not-appear')
        cookie.chmod(0o600)
        for scenario in ('ok', 'snapshot', 'ibd', 'timeout', 'unsupported', 'missing', 'mempool-spend'):
            with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
                server.records, server.scenario = [], scenario
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    result = subprocess.run([args.driver, '--http', f'http://127.0.0.1:{server.server_port}/', cookie],
                                            capture_output=True, text=True, timeout=5)
                    assert result.returncode == 0 and 'private-cookie' not in result.stdout+result.stderr
                    assert 'server-secret' not in result.stdout+result.stderr
                    value = json.loads(result.stdout)
                    assert value['node_status'] == (0 if scenario in ('timeout', 'unsupported') else 4)
                    if scenario == 'snapshot':
                        assert not value['validated']
                    if scenario == 'ibd':
                        assert value['ibd']
                    assert value['output_status'] == (2 if scenario in ('missing', 'mempool-spend') else 0)
                    assert value['amount_sats'] == (0 if scenario in ('missing', 'mempool-spend') else 1)
                    assert all(x['method'] in ('getblockchaininfo', 'getchainstates', 'gettxout') for x in server.records)
                    count += 1
                finally:
                    server.shutdown()
                    thread.join(timeout=2)
                    assert not thread.is_alive()
            # server_close joins all owned request threads, including timeout.
        if args.core32:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            import bitcoin_core_signing_regtest as core
            core.validate_inputs(args.core32, args.oracle)
            with core.Node(args.core32) as node:
                result = subprocess.run([args.driver, '--http', f'http://127.0.0.1:{node.port}/', node.cookie],
                                        capture_output=True, text=True, timeout=10)
                assert result.returncode == 0
                value = json.loads(result.stdout)
                assert value['node_status'] == 4 and value['validated']
                assert value['output_status'] == 2 and value['amount_sats'] == 0
                count += 1
    print(json.dumps(dict(executed=count, failed=0, skipped=0, core=bool(args.core32), owned_processes_remaining=0)))

if __name__ == '__main__':
    main()
