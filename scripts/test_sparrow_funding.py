#!/usr/bin/env python3
"""Offline fixtures/mocks only. Optional installed Sparrow test uses fresh unfunded wallets."""
import argparse
from copy import deepcopy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import sparrow_funding as offline
import sparrow_signer as files
import signet_funding as live


def address(payload):
    data = b'\x6f'+bytes([payload])*20
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    number = int.from_bytes(data,'big'); result = ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while number:
        number,digit = divmod(number,58); result = alphabet[digit]+result
    return result


def wire(outputs, *, txid='11'*32, vout=0, script=b'', sequence=0xffffffff):
    raw = struct.pack('<I',2)+b'\x01'+bytes.fromhex(txid)[::-1]+struct.pack('<I',vout)
    raw += bytes([len(script)])+script+struct.pack('<I',sequence)+bytes([len(outputs)])
    for amount,script in outputs:
        data = bytes.fromhex(script); raw += struct.pack('<Q',amount)+bytes([len(data)])+data
    return (raw+b'\0'*4).hex()


def fixture():
    source,change,destination = [address(n) for n in [1,2,3]]
    parent = wire([(10000,offline.p2pkh_script(source))])
    intent = {'network':'signet','genesis':offline.GENESIS,'sourceTransaction':parent,
              'sourceTxid':offline.transaction(parent)['txid'],'sourceVout':0,'sourceAddress':source,
              'sourceValueSats':10000,'changeAddress':change,'changeScript':offline.p2pkh_script(change),
              'destinationAddress':destination,'destinationScript':offline.p2pkh_script(destination),
              'amountSats':3000,'feeSats':300}
    raw = wire([(3000,intent['destinationScript']),(6700,intent['changeScript'])],
               txid=intent['sourceTxid'],script=b'\x01'*106)
    audit = offline.audit_transaction(intent,raw)
    audit.update({'intentSha256':offline.sha(offline.canonical(intent)),'signatureVerified':True,
                  'provenance':{'fixture':'mock signature; never a live transaction'}})
    return intent,raw,audit


class FakeCore:
    wallet = 'quietproof-disposable-fixture'

    def __init__(self,intent,raw,audit):
        self.intent,self.raw,self.audit = intent,raw,audit
        self.calls = []; self.sent = 0; self.known = False; self.timeout = False
        self.chain = {'chain':'signet','initialblockdownload':False,'blocks':20,'headers':20,'bestblockhash':'22'*32}
        self.owned = True; self.source = True; self.relay = True

    def call(self,method,params=None,*,wallet=False):
        self.calls.append(method); params = params or []
        if method=='getnetworkinfo': return {'version':320100}
        if method=='getblockhash': return offline.GENESIS
        if method=='getblockchaininfo': return self.chain
        if method=='getchainstates': return {'chainstates':[{'validated':True,'bestblockhash':'22'*32}]}
        if method=='getwalletinfo': return {'walletname':self.wallet,'descriptors':True,'private_keys_enabled':True,'external_signer':False}
        if method=='getaddressinfo': return {'ismine':self.owned,'iswatchonly':False,'iscompressed':True,
            'iswitness':False,'isscript':False,'scriptPubKey':self.intent['destinationScript'],'pubkey':'02'+'01'*32}
        if method=='gettxout':
            if params[0]==self.intent['sourceTxid']:
                return {'confirmations':2,'value':'0.00010000','scriptPubKey':{'hex':offline.p2pkh_script(self.intent['sourceAddress'])}} if self.source else None
            if self.known:
                return {'confirmations':1,'value':'0.00003000','scriptPubKey':{'hex':self.intent['destinationScript']}}
            return None
        if method=='decoderawtransaction': return {'txid':self.audit['txid'],'vsize':226,
            'vin':[{'txid':self.intent['sourceTxid'],'vout':0}],
            'vout':[{'value':'0.00003000','scriptPubKey':{'hex':self.intent['destinationScript']}},
                    {'value':'0.00006700','scriptPubKey':{'hex':self.intent['changeScript']}}]}
        if method=='testmempoolaccept': return [{'txid':self.audit['txid'],'allowed':self.relay,'fees':{'base':'0.00000300'}}]
        if method in ['getmempoolentry','gettransaction']: raise live.RpcError(-5)
        if method=='sendrawtransaction':
            self.sent += 1; self.known = True
            if self.timeout: raise TimeoutError('fixture timeout after remote commit')
            return self.audit['txid']
        raise AssertionError(method)


class FundingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.intent,self.raw,self.audit = fixture()
        self.bundle = self.root/'bundle'; self.bundle.mkdir(mode=0o700)
        for name,value in [('intent.json',offline.canonical(self.intent)),('signed.hex',(self.raw+'\n').encode()),
                           ('audit.json',offline.canonical(self.audit))]: files.write_private(self.bundle/name,value)
        self.core = FakeCore(self.intent,self.raw,self.audit)

    def test_fixture_decode_and_exact_audit(self):
        self.assertEqual(offline.audit_transaction(self.intent,self.raw)['feeSats'],300)
        self.assertEqual(live.load_bundle(self.bundle)[2]['txid'],self.audit['txid'])

    def test_incorrect_network_and_genesis(self):
        for key,value in [('network','mainnet'),('genesis','00'*32)]:
            with self.subTest(key=key):
                intent = dict(self.intent,**{key:value})
                with self.assertRaises(ValueError): offline.validate_intent(intent)

    def test_destination_script_and_address_mismatch(self):
        for key,value in [('destinationAddress',address(4)),('destinationScript',self.intent['changeScript'])]:
            with self.subTest(key=key),self.assertRaises(ValueError): offline.validate_intent(dict(self.intent,**{key:value}))

    def test_wrong_source_txid_index_value_script(self):
        for key,value in [('sourceTxid','00'*32),('sourceVout',2),('sourceValueSats',10001),('sourceAddress',address(4))]:
            with self.subTest(key=key),self.assertRaises(ValueError): offline.validate_intent(dict(self.intent,**{key:value}))

    def test_amount_fee_cap_and_integer_contract(self):
        for key,value in [('amountSats',2999),('amountSats',3001),('feeSats',501),('feeSats',0),('feeSats',-1),('feeSats',True),('sourceVout',0.0)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError): offline.validate_intent(dict(self.intent,**{key:value}))

    def test_dust_and_same_recipient_rejected(self):
        intent = dict(self.intent,sourceValueSats=3500)
        intent['sourceTransaction'] = wire([(3500,offline.p2pkh_script(intent['sourceAddress']))])
        intent['sourceTxid'] = offline.transaction(intent['sourceTransaction'])['txid']
        with self.assertRaises(ValueError): offline.validate_intent(intent)
        intent = dict(self.intent,destinationAddress=self.intent['changeAddress'],destinationScript=self.intent['changeScript'])
        with self.assertRaises(ValueError): offline.validate_intent(intent)

    def test_bad_change_and_extra_fields(self):
        for delta in [{'changeAddress':address(4)},{'extra':'ignored'}]:
            with self.subTest(delta=delta),self.assertRaises(ValueError): offline.validate_intent(dict(self.intent,**delta))

    def test_signed_input_and_outputs_exact(self):
        variants = [wire([(3000,self.intent['destinationScript']),(6700,self.intent['changeScript'])],script=b'\x01'*106),
                    wire([(3001,self.intent['destinationScript']),(6699,self.intent['changeScript'])],txid=self.intent['sourceTxid'],script=b'\x01'*106),
                    wire([(3000,self.intent['destinationScript']),(6700,self.intent['destinationScript'])],txid=self.intent['sourceTxid'],script=b'\x01'*106)]
        for raw in variants:
            with self.subTest(raw=offline.sha(raw.encode())),self.assertRaises(ValueError): offline.audit_transaction(self.intent,raw)

    def test_trailing_truncated_and_noncanonical_wire(self):
        for raw in [self.raw+'00',self.raw[:-2],self.raw[:8]+'fd0100'+self.raw[10:]]:
            with self.subTest(raw=offline.sha(raw.encode())),self.assertRaises(ValueError): offline.transaction(raw)

    def test_witness_parent_txid_excludes_witness(self):
        # Same base transaction with a one-item synthetic witness. No signing.
        raw = self.intent['sourceTransaction']
        witness = raw[:8]+'0001'+raw[8:-8]+'010101'+raw[-8:]
        self.assertEqual(offline.transaction(witness)['txid'],self.intent['sourceTxid'])

    def test_unsafe_private_inputs_symlinks_and_outputs(self):
        path = self.root/'unsafe'; path.write_bytes(b'private'); path.chmod(0o644)
        with self.assertRaises(ValueError): files.read_file(path,private=True)
        link = self.root/'link'; link.symlink_to(self.bundle/'intent.json')
        with self.assertRaises(OSError): files.read_file(link,private=True)
        with self.assertRaises(FileExistsError): live.durable_new(self.bundle/'intent.json',{})

    def test_bundle_tampering(self):
        (self.bundle/'audit.json').write_bytes(offline.canonical(dict(self.audit,txid='00'*32)))
        with self.assertRaises(ValueError): live.load_bundle(self.bundle)

    def test_audit_has_no_mutating_rpc(self):
        result = live.audit_live(self.core,self.bundle)
        self.assertTrue(result['relayAllowed']); self.assertEqual(self.core.sent,0)
        self.assertNotIn('sendrawtransaction',self.core.calls)
        self.assertFalse(any(x in self.core.calls for x in ['walletpassphrase','dumpprivkey','fundrawtransaction']))

    def test_unowned_core_destination_and_spent_source(self):
        self.core.owned = False
        with self.assertRaises(ValueError): live.audit_live(self.core,self.bundle)
        self.core.owned = True; self.core.source = False
        with self.assertRaises(ValueError): live.audit_live(self.core,self.bundle)

    def test_ibd_wrong_network_unvalidated_rejected(self):
        for delta in [{'initialblockdownload':True},{'chain':'regtest'},{'headers':21}]:
            self.core.chain.update(delta)
            with self.subTest(delta=delta),self.assertRaises(ValueError): live.audit_live(self.core,self.bundle)
            self.core = FakeCore(self.intent,self.raw,self.audit)

    def test_relay_failure_prevents_attempt(self):
        self.core.relay = False
        with self.assertRaises(ValueError): live.broadcast(self.core,self.bundle,self.audit['txid'])
        self.assertFalse((self.bundle/'broadcast-attempt.json').exists()); self.assertEqual(self.core.sent,0)

    def test_wrong_txid_cannot_broadcast(self):
        with self.assertRaises(ValueError): live.broadcast(self.core,self.bundle,'00'*32)
        self.assertEqual(self.core.sent,0)

    def test_broadcast_once_and_reentry_reconciles(self):
        self.assertEqual(live.broadcast(self.core,self.bundle,self.audit['txid'])['status'],'confirmed')
        self.assertEqual(live.broadcast(self.core,self.bundle,self.audit['txid'])['status'],'confirmed')
        self.assertEqual(self.core.sent,1)
        self.assertEqual((self.bundle/'broadcast-attempt.json').stat().st_mode&0o777,0o600)

    def test_durable_attempt_exists_before_network_write(self):
        original = self.core.call
        def call(method,params=None,**kwargs):
            if method == 'sendrawtransaction':
                saved = json.loads(files.read_file(self.bundle/'broadcast-attempt.json',private=True))
                self.assertEqual(saved['rawTransactionSha256'],self.audit['rawTransactionSha256'])
            return original(method,params,**kwargs)
        self.core.call = call
        live.broadcast(self.core,self.bundle,self.audit['txid'])

    def test_timeout_reconciles_without_resubmission(self):
        self.core.timeout = True
        with self.assertRaises(TimeoutError): live.broadcast(self.core,self.bundle,self.audit['txid'])
        self.assertTrue((self.bundle/'broadcast-attempt.json').exists())
        self.assertEqual(live.broadcast(self.core,self.bundle,self.audit['txid'])['status'],'confirmed')
        self.assertEqual(self.core.sent,1)

    def test_unknown_attempt_never_retries(self):
        live.durable_new(self.bundle/'broadcast-attempt.json',self.audit)
        self.assertEqual(live.broadcast(self.core,self.bundle,self.audit['txid'])['status'],'unknown')
        self.assertEqual(self.core.sent,0)

    def test_existing_bundle_never_resigns(self):
        path = self.root/'intent'; files.write_private(path,offline.canonical(self.intent))
        args = SimpleNamespace(intent=path,output=self.bundle)
        with patch.object(offline,'adapter') as adapter:
            with self.assertRaises(ValueError): offline.prepare(args)
            adapter.assert_not_called()

    def test_no_secret_logs_on_rejection(self):
        out,err = io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            rc = live.main(['audit','--bundle',str(self.bundle),'--rpc-url','http://example.org:38332',
                            '--cookie',str(self.root/'secret-cookie'),'--wallet',self.core.wallet,
                            '--output',str(self.root/'result')])
        self.assertEqual(rc,1); self.assertEqual(out.getvalue(),'')
        self.assertNotIn('secret-cookie',err.getvalue()); self.assertNotIn(self.raw,err.getvalue())

    def test_offline_error_does_not_disclose_library_details(self):
        out,err = io.StringIO(),io.StringIO()
        with patch.object(offline,'adapter',side_effect=ValueError('fixture-secret-key-data')):
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                rc = offline.main(['describe','--sparrow',str(self.root),'--jdk',str(self.root),
                                   '--cache',str(self.root),'--wallet-dir',str(self.root)])
        self.assertEqual(rc,1); self.assertEqual(out.getvalue(),'')
        self.assertNotIn('fixture-secret-key-data',err.getvalue())

    def test_cookie_and_endpoint_fail_closed(self):
        cookie = self.root/'cookie'; files.write_private(cookie,b'__cookie__:fixture-secret')
        for url in ['https://127.0.0.1:38332','http://localhost:38332','http://127.0.0.1:38332/wallet/x',
                    'http://u:p@127.0.0.1:38332','http://example.com:38332']:
            with self.subTest(url=url),self.assertRaises(ValueError): live.Core(url,cookie,self.core.wallet)
        with self.assertRaises(ValueError): live.Core('http://127.0.0.1:38332',cookie,'production')


class InstalledTests(unittest.TestCase):
    def test_stock_signing_owned_input_change_and_original_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='funding-test-') as temporary:
            root = Path(temporary); root.chmod(0o700); wallet = root/'wallet'
            common = ['--sparrow',str(INSTALLED.sparrow),'--jdk',str(INSTALLED.jdk),'--cache',str(INSTALLED.cache),
                      '--network','signet','--wallet-dir',str(wallet),'--script-kind','p2pkh']
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(files.main(['create']+common),0)
            original = {p.name:offline.sha(p.read_bytes()) for p in wallet.iterdir()}
            args = SimpleNamespace(sparrow=INSTALLED.sparrow,jdk=INSTALLED.jdk,cache=INSTALLED.cache,wallet_dir=wallet)
            owned,_ = offline.adapter(args,'describe')
            intent,_,_ = fixture(); intent.update({k:owned[k] for k in ['sourceAddress','changeAddress','changeScript']})
            intent['sourceTransaction'] = wire([(10000,owned['sourceScript'])])
            intent['sourceTxid'] = offline.transaction(intent['sourceTransaction'])['txid']
            result,_ = offline.adapter(args,'prepare',intent)
            self.assertTrue(result['signatureVerified']); offline.audit_transaction(intent,result['rawTransaction'])
            for delta in [{'sourceAddress':address(4)},{'changeAddress':address(4),'changeScript':offline.p2pkh_script(address(4))}]:
                with self.subTest(delta=delta),self.assertRaises(ValueError): offline.adapter(args,'prepare',dict(intent,**delta))
            self.assertEqual(original,{p.name:offline.sha(p.read_bytes()) for p in wallet.iterdir()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--sparrow',type=Path); parser.add_argument('--jdk',type=Path)
    parser.add_argument('--cache',type=Path); INSTALLED,remaining = parser.parse_known_args()
    os.umask(0o077)
    if not all([INSTALLED.sparrow,INSTALLED.jdk,INSTALLED.cache]):
        InstalledTests = unittest.skip('explicit installed Sparrow/JDK/cache not supplied')(InstalledTests)
    unittest.main(argv=[__file__]+remaining)
