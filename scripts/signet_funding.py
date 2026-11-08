#!/usr/bin/env python3
"""Explicit localhost orchestration for an already prepared disposable transfer.

audit is read-only at Core. broadcast requires the exact persisted txid, records
an exclusive durable attempt before submission and never resubmits on reentry.
No ordinary proof/import command imports this module or invokes this tool.
"""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import base64

import sparrow_signer as files
from sparrow_funding import GENESIS, audit_transaction, canonical, sha, transaction, validate_intent

require = files.require


def now():
    return datetime.now(timezone.utc).isoformat()


def durable_new(path, value):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RpcError(ValueError):
    def __init__(self, code):
        super().__init__('localhost RPC rejected operation')
        self.code = code


class Core:
    def __init__(self, url, cookie, wallet):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                and parsed.port is not None and not parsed.username and not parsed.password
                and parsed.path in ['', '/'] and not parsed.query and not parsed.fragment,
                'explicit IPv4 localhost RPC required')
        require(wallet.startswith('quietproof-disposable-') and '/' not in wallet
                and all(c.isalnum() or c in '-_' for c in wallet), 'disposable Core wallet required')
        token = files.read_file(cookie,private=True).strip()
        require(token.startswith(b'__cookie__:') and b'\n' not in token, 'cookie authentication required')
        self.url = url.rstrip('/')
        self.wallet = wallet
        self.auth = 'Basic '+base64.b64encode(token).decode()
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, params=None, *, wallet=False):
        require(method in {'getblockhash','getblockchaininfo','getchainstates','getnetworkinfo',
                          'getwalletinfo','getaddressinfo','gettxout','decoderawtransaction',
                          'testmempoolaccept','getmempoolentry','gettransaction','sendrawtransaction'},
                'RPC method outside funding contract')
        url = self.url + ('/wallet/'+urllib.parse.quote(self.wallet,safe='') if wallet else '/')
        body = canonical({'jsonrpc':'2.0','id':'disposable-funding','method':method,'params':params or []})
        request = urllib.request.Request(url,data=body,headers={'Authorization':self.auth,'Content-Type':'application/json'})
        try:
            response = self.http.open(request,timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(1024*1024+1)
        require(len(data) <= 1024*1024, 'bounded RPC response required')
        reply = json.loads(data,parse_float=Decimal)
        if reply.get('error'):
            raise RpcError(reply['error'].get('code'))
        return reply['result']


def load_bundle(bundle):
    files.private_directory(bundle)
    intent_data = files.read_file(bundle/'intent.json',private=True)
    intent = json.loads(intent_data); validate_intent(intent)
    require(intent_data == canonical(intent), 'canonical immutable intent required')
    signed = files.read_file(bundle/'signed.hex',private=True)
    require(signed.endswith(b'\n') and signed.count(b'\n') == 1, 'exact signed hex file required')
    raw = signed[:-1].decode('ascii')
    derived = audit_transaction(intent,raw)
    audit = json.loads(files.read_file(bundle/'audit.json',private=True))
    require(all(audit.get(k) == v for k,v in derived.items())
            and audit.get('intentSha256') == sha(intent_data)
            and audit.get('signatureVerified') is True, 'persisted audit mismatch')
    return intent,raw,audit


def sats(amount):
    value = Decimal(str(amount))*100000000
    require(value == value.to_integral_value(), 'whole satoshis required')
    return int(value)


def validate_node(core):
    network = core.call('getnetworkinfo')
    chain = core.call('getblockchaininfo')
    states = core.call('getchainstates')
    require(network['version'] == 320100, 'pinned Core 32.1 required')
    require(core.call('getblockhash',[0]) == GENESIS and chain['chain'] == 'signet'
            and chain['initialblockdownload'] is False and chain['blocks'] == chain['headers'],
            'synchronized public signet required')
    require(len(states['chainstates']) == 1 and states['chainstates'][0]['validated'] is True
            and states['chainstates'][0]['bestblockhash'] == chain['bestblockhash'], 'validated chainstate required')
    return {'observedAt':now(),'coreVersion':network['version'],'height':chain['blocks'],
            'bestblockhash':chain['bestblockhash'],'ibd':False,'validated':True,'genesis':GENESIS}


def validate_wallet(core, intent):
    wallet = core.call('getwalletinfo',wallet=True)
    address = core.call('getaddressinfo',[intent['destinationAddress']],wallet=True)
    require(wallet['walletname'] == core.wallet and wallet['descriptors'] is True
            and wallet['private_keys_enabled'] is True and wallet.get('external_signer') is False,
            'private-key descriptor wallet required')
    require(address['ismine'] is True and address['iswatchonly'] is False
            and address['iscompressed'] is True and address['iswitness'] is False
            and address['isscript'] is False and address['scriptPubKey'] == intent['destinationScript']
            and len(address['pubkey']) == 66 and address['pubkey'][:2] in ['02','03'],
            'Core-owned compressed P2PKH destination required')
    return {'wallet':core.wallet,'destinationAddress':intent['destinationAddress'],
            'ismine':True,'privateKeysEnabled':True,'descriptors':True,'compressed':True,
            'pubkey':address['pubkey'],'script':address['scriptPubKey']}


def audit_live(core, bundle):
    intent,raw,audit = load_bundle(bundle)
    node = validate_node(core); wallet = validate_wallet(core,intent)
    source = core.call('gettxout',[intent['sourceTxid'],intent['sourceVout'],True])
    require(source is not None and source['confirmations'] >= 1
            and sats(source['value']) == intent['sourceValueSats']
            and source['scriptPubKey']['hex'] == transaction(intent['sourceTransaction'])['outputs'][intent['sourceVout']]['script'],
            'confirmed current source UTXO required')
    decoded = core.call('decoderawtransaction',[raw])
    require(decoded['txid'] == audit['txid'] and len(decoded['vin']) == 1 and len(decoded['vout']) == 2,
            'independent Core decode mismatch')
    require(decoded['vin'][0]['txid'] == intent['sourceTxid'] and decoded['vin'][0]['vout'] == intent['sourceVout'],
            'Core decoded input mismatch')
    for output, amount, script in zip(decoded['vout'],[3000,audit['changeSats']],
                                    [intent['destinationScript'],intent['changeScript']]):
        require(sats(output['value']) == amount and output['scriptPubKey']['hex'] == script,
                'Core decoded recipient/change mismatch')
    relay = core.call('testmempoolaccept',[[raw],'0.0001'])
    require(len(relay) == 1 and relay[0].get('allowed') is True
            and relay[0]['txid'] == audit['txid'] and sats(relay[0]['fees']['base']) == audit['feeSats'],
            'read-only relay simulation rejected transfer')
    return {'observedAt':now(),'txid':audit['txid'],'rawTransactionSha256':audit['rawTransactionSha256'],
            'intentSha256':audit['intentSha256'],'node':node,'wallet':wallet,
            'sourceConfirmations':source['confirmations'],'sourceValueSats':intent['sourceValueSats'],
            'sourceAddress':intent['sourceAddress'],'changeAddress':intent['changeAddress'],
            'changeSats':audit['changeSats'],'amountSats':3000,'feeSats':audit['feeSats'],
            'relayAllowed':True,'vsize':relay[0].get('vsize_bip141',decoded['vsize'])}


def reconcile(core, intent, audit):
    node = validate_node(core); validate_wallet(core,intent)
    output = core.call('gettxout',[audit['txid'],0,True])
    if output is not None:
        require(sats(output['value']) == 3000 and output['scriptPubKey']['hex'] == intent['destinationScript'],
                'funded output mismatch')
        return {'txid':audit['txid'],'status':'confirmed' if output['confirmations'] > 0 else 'mempool',
                'confirmations':output['confirmations'],'node':node,'observedAt':now()}
    try:
        entry = core.call('getmempoolentry',[audit['txid']])
        require(entry is not None,'mempool entry required')
        return {'txid':audit['txid'],'status':'mempool','confirmations':0,'node':node,'observedAt':now()}
    except RpcError as error:
        if error.code != -5:
            raise
    try:
        tx = core.call('gettransaction',[audit['txid']],wallet=True)
        return {'txid':audit['txid'],'status':'wallet-observed','confirmations':tx['confirmations'],
                'node':node,'observedAt':now()}
    except RpcError as error:
        if error.code not in [-5,-8]:
            raise
    return {'txid':audit['txid'],'status':'unknown','confirmations':None,'node':node,'observedAt':now()}


def broadcast(core,bundle,expected_txid):
    intent,raw,audit = load_bundle(bundle)
    require(expected_txid == audit['txid'], 'exact prepared txid acknowledgement required')
    state = bundle/'broadcast-attempt.json'
    if state.exists() or state.is_symlink():
        previous = json.loads(files.read_file(state,private=True))
        require(previous['txid'] == audit['txid'] and previous['rawTransactionSha256'] == audit['rawTransactionSha256'],
                'broadcast attempt identity mismatch')
        # Even an ambiguous timeout is never retried. Reconcile these same bytes.
        return reconcile(core,intent,audit)
    known = reconcile(core,intent,audit)
    if known['status'] != 'unknown':
        return known
    live = audit_live(core,bundle)
    durable_new(state,{'txid':audit['txid'],'rawTransactionSha256':audit['rawTransactionSha256'],
                       'intentSha256':audit['intentSha256'],'attemptedAt':now(),'audit':live})
    # Timeout/process failure leaves the attempt in place: a rerun only reconciles.
    txid = core.call('sendrawtransaction',[raw,'0.0001'])
    require(txid == audit['txid'],'broadcast txid mismatch')
    result = reconcile(core,intent,audit)
    durable_new(bundle/'broadcast-result.json',result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['audit','broadcast','reconcile'])
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--rpc-url',required=True); parser.add_argument('--cookie',type=Path,required=True)
    parser.add_argument('--wallet',required=True); parser.add_argument('--txid')
    parser.add_argument('--output',type=Path,required=True,help='new owner-only public audit result')
    args = parser.parse_args(argv); os.umask(0o077)
    try:
        require(not args.output.exists() and not args.output.is_symlink(),'new result file required')
        files.private_directory(args.output.parent)
        core = Core(args.rpc_url,args.cookie,args.wallet)
        if args.action == 'audit':
            result = audit_live(core,args.bundle)
        elif args.action == 'broadcast':
            result = broadcast(core,args.bundle,args.txid)
        else:
            intent,_,audit = load_bundle(args.bundle); result = reconcile(core,intent,audit)
        durable_new(args.output,result)
        print(json.dumps(result,sort_keys=True))
        return 2 if result.get('status') == 'unknown' else 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,urllib.error.URLError):
        print('Localhost funding operation rejected or uncertain; reconcile persisted txid, never resign/resubmit',file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
