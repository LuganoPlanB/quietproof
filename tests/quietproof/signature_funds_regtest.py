#!/usr/bin/env python3
"""Production CLI wallet/proof/funds acceptance on owned disposable Core32.

Four signature proofs cover online and RPC-OFF delegated proving for both
profiles over mixed real claims. Private receipts/credentials are ephemeral.
Fixture-only spending is separate from the audited product signing path.
"""
import argparse
import copy
import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_core_signing_regtest as core
import signing_reference as ref

require = core.require
MODE = ['--proof-mode', 'signature-possession']
VERIFIER = 'core32.funds.example'
MESSAGE = 'production wallet-to-funds qualification'

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class AuditHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        server = self.server
        try:
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            method, params = request['method'], request['params']
            server.records.append(method)
            allowed = ({'getblockchaininfo', 'getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet'}
                       if server.phase == 'sign' else {'getblockchaininfo', 'getchainstates', 'gettxout'})
            require(method in allowed, 'forbidden product RPC')
            wallet = None if self.path == '/' else unquote(self.path.removeprefix('/wallet/'))
            if method in ('getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet'):
                require(self.path.startswith('/wallet/') and wallet == server.wallet, 'wallet selection changed')
            else:
                require(wallet is None, 'chain query used wallet authority')
            if method == 'signrawtransactionwithwallet':
                p = server.profile
                require(params == [p['unsigned'].hex(), [{'txid': p['parent_id'][::-1].hex(), 'vout': 0,
                    'scriptPubKey': p['script'].hex(), 'amount': 0}], 'ALL'], 'unsafe signing shape')
            if method == 'gettxout':
                require(len(params) == 3 and params[2] is True and
                        (params[0], params[1]) in server.outpoints, 'wrong real outpoint/mempool policy')
            value = server.node.call(method, *params, wallet=wallet)
            response = dict(jsonrpc='2.0', id=request['id'], result=value)
        except Exception:
            server.errors.append('audited product RPC failed')
            response = dict(jsonrpc='2.0', id=request.get('id') if 'request' in locals() else None,
                            error=dict(code=-8, message='isolated audit rejected request'))
        data = json.dumps(response).encode()
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

class Runner:
    def __init__(self, work):
        self.work, self.checks, self.snapshots, self.children = work, [], [], []
        self.secrets = []
        self.audit = None
        self.manifest = dict(startedAt=utc(), status='running', checks=self.checks, snapshots=self.snapshots)

    def persist(self):
        (self.work/'manifest.json').write_text(json.dumps(self.manifest, indent=2)+'\n')

    def run(self, label, command, expected=0, *, cwd=None, env=None, secret_input=None, timeout=30):
        print('START', label, flush=True)
        if self.audit:
            self.audit.records.clear()
            self.audit.errors.clear()
        observed = utc()
        child = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.children.append(child)
        self.manifest['activeProcess'] = dict(id=label, pid=child.pid, startedAt=observed)
        self.persist()
        print('PROCESS', label, child.pid, flush=True)
        timed_out = False
        try:
            output, error = child.communicate(input=secret_input or b'', timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            output, error = child.communicate(timeout=5)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=5)
            raise
        finally:
            self.manifest['activeProcess'] = None
            self.persist()
        combined = output+error
        leaked = any(value and value in combined for value in self.secrets)
        stdout, stderr = self.work/(label+'.stdout'), self.work/(label+'.stderr')
        stdout.write_bytes(b'[private diagnostic suppressed]\n' if leaked else output)
        stderr.write_bytes(b'[private diagnostic suppressed]\n' if leaked else error)
        self.checks.append(dict(id=label, command=list(map(str, command)), cwd=str(cwd or Path.cwd()),
            pid=child.pid, exit=child.returncode, expectedExit=expected, timedOut=timed_out, startedAt=observed, observedAt=utc(),
            stdout=dict(path=str(stdout), sha256=sha(stdout)), stderr=dict(path=str(stderr), sha256=sha(stderr)),
            rpcMethods=list(self.audit.records) if self.audit else [], stdin='protected disposable scalar' if secret_input else 'empty'))
        self.persist()
        require(not leaked, 'private diagnostic disclosure: '+label)
        require(not timed_out, 'command deadline exceeded: '+label)
        require(child.returncode == expected, 'unexpected command exit: '+label)
        require(not self.audit or not self.audit.errors, 'RPC audit failure: '+label)
        print('PASS', label, flush=True)
        return output, error

    def unchanged(self, node, wallet, label, operation):
        before = core.state_snapshot(node, wallet)
        result = operation()
        after = core.state_snapshot(node, wallet)
        b = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
        a = hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()
        self.snapshots.append(dict(id=label, beforeSha256=b, afterSha256=a, equal=before == after))
        self.persist()
        require(before == after, 'product operation changed real funds state: '+label)
        return result

def claim_options(request):
    options = []
    for c in request['claims']:
        options += ['--claim', f"{c['txid_display']}:{c['vout']}:{c['amount_sats']}:{'p2pkh' if c['script_kind'] else 'p2wpkh'}:{c['program']}"]
    return options

def retained_request(path, summary, template):
    request = copy.deepcopy(template)
    wire = path.read_bytes()
    offset = 10
    for _ in range(2):
        length = int.from_bytes(wire[offset:offset+2], 'big')
        offset += 2+length
    request.update(verifier=VERIFIER, purpose='proof-of-funds', nonce=wire[offset:offset+32].hex(),
                   bip322_message_hash=ref.tagged('BIP0322-signed-message', MESSAGE.encode()).hex(),
                   not_before=summary['request_created_at'], expires_at=summary['expires_at'])
    require(ref.request_bytes(request) == wire, 'issued request differs from independent canonical encoder')
    return request

def proof_semantics(path, request):
    wire = path.read_bytes()
    require(wire[:5] == b'QPE1\x03', 'wrong signature envelope version')
    count = int.from_bytes(wire[5:9], 'big')
    require(wire[9:9+count] == request.read_bytes(), 'proof does not contain retained request')
    tail = 9+count
    require(wire[tail+8:tail+13] == b'\x01\x00\x01\x00\x01', 'wrong proof mode/profile/family')
    return wire[9:9+count], wire[tail+8:tail+57]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--core32', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--prefix-path', required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    core.validate_inputs(args.core32, args.oracle)
    args.work.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='signature-funds-', dir=args.work))
    runner = Runner(work)
    print('evidence', work, flush=True)
    runner.persist()
    offline_build = work/'offline-build'
    runner.run('configure-offline', ['cmake', '-S', args.source, '-B', offline_build, '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=OFF', '-DQUIETPROOF_BUILD_RPC=OFF',
        '-DQUIETPROOF_BUILD_SIGNATURE_MODE=ON', '-DCMAKE_PREFIX_PATH='+args.prefix_path], timeout=60)
    runner.run('build-offline', ['cmake', '--build', offline_build, '--parallel', '2', '--target', 'quietproof-cli'], timeout=300)
    offline = offline_build/'quietproof'
    require('QUIETPROOF_BUILD_RPC:BOOL=OFF' in (offline_build/'CMakeCache.txt').read_text(), 'delegated binary has RPC transport')
    public = work/'public'; public.mkdir()
    signature_proofs = []
    node_process = None
    try:
        with tempfile.TemporaryDirectory(prefix='private-', dir=work) as private_dir, core.Node(args.core32) as node:
            node_process = node.process
            private = Path(private_dir)
            wallet, coins = core.mature_fixture(node, 'funds production /?')
            runner.secrets += [node.cookie.read_bytes().strip(), node.cookie.read_bytes().strip().split(b':', 1)[1],
                               ('0'*63+'1').encode(), core.disposable_wif(1).encode()]
            audit = ThreadingHTTPServer(('127.0.0.1', 0), AuditHandler)
            audit.node, audit.wallet = node, wallet['wallet']
            audit.phase, audit.profile, audit.records, audit.errors = 'sign', None, [], []
            audit.outpoints = {(c['txid'], c['vout']) for group in coins.values() for c in group}
            thread = threading.Thread(target=audit.serve_forever)
            proxy_cookie = private/'cookie'; proxy_cookie.write_text('fixture:ephemeral-funds-cookie'); proxy_cookie.chmod(0o600)
            runner.secrets.append(b'ephemeral-funds-cookie')
            rpc = ['--rpc-url', f'http://127.0.0.1:{audit.server_port}/', '--rpc-cookie', proxy_cookie, '--rpc-timeout', '5']
            runner.audit = audit
            thread.start()
            try:
                profiles = []
                for kind in (1, 0):
                    label = 'p2pkh' if kind else 'p2wpkh'
                    request_path, receipt_path = public/(label+'.qpr'), private/(label+'.qpa')
                    template = core.request_for_coins(wallet, coins, kind)
                    out, _ = runner.run(label+'-request', [args.cli, 'challenge', 'create', *MODE, '--network', 'regtest',
                        '--verifier', VERIFIER, '--purpose', 'proof-of-funds', '--message', MESSAGE, '--expires-in', '21600',
                        '--signing-kind', label, '--output', request_path, *claim_options(template)])
                    request = retained_request(request_path, json.loads(out), template)
                    audit.phase, audit.profile = 'sign', ref.virtual_profile(request)
                    runner.unchanged(node, wallet['wallet'], label+'-authorize', lambda:
                        runner.run(label+'-authorize', [args.cli, 'authorize', *MODE, '--request', request_path,
                            '--receipt-output', receipt_path, '--rpc-wallet', wallet['wallet'], *rpc]))
                    require(audit.records == ['getblockchaininfo', 'getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet'], 'authorization RPC authority changed')
                    receipt = receipt_path.read_bytes()
                    require(receipt_path.stat().st_mode & 0o777 == 0o600, 'receipt is not owner-only')
                    validated = ref.validate_signed_response(request, dict(complete=True, hex=receipt[44:].hex()), args.oracle)
                    runner.secrets += [receipt.hex().encode(), receipt[44:].hex().encode(), validated['signature'].hex().encode()]
                    profiles.append((label, request, request_path, receipt_path))

                # Fixture operator locks/unlocks explicitly. The product proxy
                # never permits walletpassphrase, private export or broadcast.
                node.call('encryptwallet', 'disposable-fixture-passphrase', wallet=wallet['wallet'])
                for label, request, request_path, receipt_path in profiles:
                    audit.phase, audit.profile = 'sign', ref.virtual_profile(request)
                    for operation in ('authorize', 'prove'):
                        output = private/(label+'-locked.'+('qpa' if operation == 'authorize' else 'qpf'))
                        output_flag = '--receipt-output' if operation == 'authorize' else '--output'
                        _, error = runner.unchanged(node, wallet['wallet'], label+'-locked-'+operation, lambda:
                            runner.run(label+'-locked-'+operation, [args.cli, operation, *MODE, '--request', request_path,
                                output_flag, output, '--rpc-wallet', wallet['wallet'], *rpc], 65))
                        require(b'locked' in error.lower() and not output.exists() and
                                audit.records == ['getblockchaininfo', 'getwalletinfo'], 'locked wallet failed at wrong boundary')
                        require(node.call('getwalletinfo', wallet=wallet['wallet'])['unlocked_until'] == 0, 'product unlocked wallet')
                node.call('walletpassphrase', 'disposable-fixture-passphrase', 3600, wallet=wallet['wallet'])

                def verify(label, proof, request_path, store, *, minimum=0, expected=0, reason=None):
                    audit.phase = 'verify'
                    out, error = runner.run(label, [args.cli, 'verify', proof, *MODE, '--expected-request', request_path,
                        '--verifier', VERIFIER, '--purpose', 'proof-of-funds', '--nonce-store', store,
                        '--minimum-total-sats', str(minimum), '--network', 'regtest', *rpc], expected, timeout=900)
                    value = json.loads(out)
                    if reason:
                        require(reason.encode() in error, 'wrong verification failure reason: '+label)
                        require(not store.exists(), 'failed verification consumed nonce: '+label)
                    else:
                        require(value['result'] == 'valid_current' and value['claims_checked'] == 2 and
                                value['coinbase_maturity'] == 'no_immature_coinbase_observed' and
                                value['quantity_label'] == 'unspent_quantity' and
                                value['verification_started_at'] <= value['proof_checked_at'] <= value['chain_observed_at'] <= value['accepted_at'],
                                'incomplete actual-node acceptance: '+label)
                    return value

                for label, request, request_path, receipt_path in profiles:
                    total = sum(c['amount_sats'] for c in request['claims'])
                    audit.phase, audit.profile = 'sign', ref.virtual_profile(request)
                    online = public/(label+'-online.qpf')
                    runner.unchanged(node, wallet['wallet'], label+'-online-proof', lambda:
                        runner.run(label+'-online-proof', [args.cli, 'prove', *MODE, '--request', request_path,
                            '--output', online, '--rpc-wallet', wallet['wallet'], *rpc], timeout=1800))
                    require(audit.records == ['getblockchaininfo', 'getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet'], 'online prover used unexpected RPC')
                    delegated = private/(label+'-delegated'); delegated.mkdir(mode=0o700)
                    shutil.copyfile(request_path, delegated/'request.qpr')
                    shutil.copyfile(receipt_path, delegated/'receipt.qpa'); (delegated/'receipt.qpa').chmod(0o600)
                    require(sorted(p.name for p in delegated.iterdir()) == ['receipt.qpa', 'request.qpr'], 'extra delegated input')
                    env = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), LANG='C', HOME=str(delegated/'absent-home'))
                    runner.unchanged(node, wallet['wallet'], label+'-delegated-proof', lambda:
                        runner.run(label+'-delegated-proof', [offline, 'prove', *MODE, '--request', 'request.qpr',
                            '--receipt-input', 'receipt.qpa', '--output', 'proof.qpf'], cwd=delegated, env=env, timeout=1800))
                    require(not audit.records and sorted(p.name for p in delegated.iterdir()) == ['proof.qpf', 'receipt.qpa', 'request.qpr'], 'delegated prover acquired extra authority/files')
                    delegated_proof = public/(label+'-delegated.qpf'); shutil.copyfile(delegated/'proof.qpf', delegated_proof)
                    require(proof_semantics(online, request_path) == proof_semantics(delegated_proof, request_path), 'online/delegated public semantics differ')
                    signature_proofs += [online, delegated_proof]
                    changed = copy.deepcopy(request); changed['nonce'] = ('01' if changed['nonce'][:2] != '01' else '02')+changed['nonce'][2:]
                    changed_path = public/(label+'-changed.qpr'); changed_path.write_bytes(ref.request_bytes(changed))
                    verify(label+'-changed-request', online, changed_path, public/(label+'-changed-nonces'), expected=67, reason='expected_request_mismatch')
                    require(not audit.records, 'changed request reached node')
                    amount_store = public/(label+'-amount-nonces')
                    verify(label+'-insufficient-value', online, request_path, amount_store, minimum=total+1, expected=5, reason='signature_minimum_total')
                    accepted = verify(label+'-failure-then-valid', online, request_path, amount_store)
                    require(accepted['total_sats'] == total and amount_store.read_text() == request['nonce']+'\n', 'real sum/final nonce differs')
                    audit.phase = 'verify'
                    out, error = runner.run(label+'-replay', [args.cli, 'verify', online, *MODE, '--expected-request', request_path,
                        '--verifier', VERIFIER, '--purpose', 'proof-of-funds', '--nonce-store', amount_store, *rpc], 67, timeout=900)
                    require(json.loads(out)['result'] == 'invalid_proof' and b'signature_request_replayed' in error and
                            amount_store.read_text() == request['nonce']+'\n', 'replay failed for unintended reason')
                    delegated_value = verify(label+'-delegated-acceptance', delegated_proof, request_path, public/(label+'-delegated-nonces'))
                    require(delegated_value['total_sats'] == total, 'delegated quantity differs from online')

                # Preserve the original scalar stdin workflow with a matching
                # stock descriptor wallet; no stock custom-export RPC exists.
                scalar_request, scalar_proof = public/'scalar.qpr', public/'scalar.qpf'
                template = copy.deepcopy(profiles[0][1]); template['claims'] = [dict(template['claims'][0])]
                runner.run('scalar-request', [args.cli, 'challenge', 'create', '--network', 'regtest', '--verifier', VERIFIER,
                    '--purpose', 'proof-of-funds', '--expires-in', '21600', '--output', scalar_request, *claim_options(template)])
                require(scalar_request.read_bytes()[4] == 2, 'scalar default changed')
                runner.unchanged(node, wallet['wallet'], 'scalar-proof', lambda:
                    runner.run('scalar-proof', [offline, 'prove', '--request', scalar_request, '--output', scalar_proof],
                               secret_input=('0'*63+'1\n').encode(), timeout=1800))
                require(not audit.records, 'scalar stdin proving contacted a wallet')
                audit.phase = 'verify'
                out, _ = runner.run('scalar-acceptance', [args.cli, 'verify', scalar_proof, '--verifier', VERIFIER,
                    '--purpose', 'proof-of-funds', '--nonce-store', public/'scalar-nonces', *rpc], timeout=900)
                require(json.loads(out)['result'] == 'valid_current' and
                        json.loads(out)['total_sats'] == template['claims'][0]['amount_sats'], 'old scalar Core workflow regressed')

                # Explicit fixture-only standard spend, after all authorisations
                # and proofs. It is never submitted through the product proxy.
                spent_kind = profiles[0][1]['claims'][0]['script_kind']
                transaction = core.real_spend_templates(coins, spent_kind, wallet['program'])[0][1]
                signed = node.call('signrawtransactionwithwallet', ref.serialize(transaction).hex(), wallet=wallet['wallet'])
                require(signed.get('complete') is True, 'fixture spend signing incomplete')
                spend_id = node.call('sendrawtransaction', signed['hex'])
                spent = coins[spent_kind][0]
                require(node.call('gettxout', spent['txid'], spent['vout'], False) is not None and
                        node.call('gettxout', spent['txid'], spent['vout'], True) is None and
                        spend_id in node.call('getrawmempool'), 'mempool spend precondition absent')
                for label, request, request_path, _ in profiles:
                    verify(label+'-mempool-spend', public/(label+'-online.qpf'), request_path,
                           public/(label+'-mempool-nonces'), expected=5, reason='signature_chain_tip_unknown')
                node.call('generatetoaddress', 1, wallet['addresses'][0])
                require(node.call('gettransaction', spend_id, wallet=wallet['wallet'])['confirmations'] == 1 and
                        node.call('gettxout', spent['txid'], spent['vout'], True) is None, 'confirmed spend precondition absent')
                for label, request, request_path, _ in profiles:
                    verify(label+'-confirmed-spend', public/(label+'-online.qpf'), request_path,
                           public/(label+'-spent-nonces'), expected=5, reason='signature_chain_tip_unknown')
                runner.manifest.update(signatureProofs=len(signature_proofs), scalarProofs=1,
                    mixedClaims=True, profiles=['p2pkh', 'p2wpkh'], fixtureSpend=dict(txid=spend_id, confirmations=1),
                    delegatedIsolation=dict(processes=2, rpcTransport=False, inputs=['request.qpr', 'receipt.qpa'],
                        stdin='empty', environmentKeys=['HOME', 'LANG', 'PATH'], credentialsPassed=False),
                    publicArtifacts=[dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(public.iterdir())])
            finally:
                runner.audit = None
                audit.shutdown(); thread.join(timeout=5); audit.server_close()
                require(not thread.is_alive(), 'audit server did not settle')
        require(not list(work.rglob('*.qpa')) and node_process.poll() is not None, 'private receipt/node survived cleanup')
        runner.manifest.update(status='complete', observedAt=utc(), executed=len(runner.checks), failed=0, skipped=0,
                               privateReceiptsRetained=0, ownedProcessesRemaining=0)
        runner.persist()
        print(json.dumps({k: runner.manifest[k] for k in ['status', 'executed', 'failed', 'skipped', 'signatureProofs', 'scalarProofs', 'ownedProcessesRemaining']}), flush=True)
        print('public evidence', work/'manifest.json', flush=True)
    finally:
        for child in runner.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL); child.communicate(timeout=5)
        require(all(child.poll() is not None for child in runner.children), 'owned command did not settle')

if __name__ == '__main__':
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt()
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupt)
    try:
        main()
    except KeyboardInterrupt:
        print('production funds qualification interrupted; owned processes cleaned up', file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        # Do not relay arbitrary RPC/parser exceptions or private fixture bytes.
        print('production funds qualification failed; inspect bounded stage logs', file=sys.stderr)
        sys.exit(1)
