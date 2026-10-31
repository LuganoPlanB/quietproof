#!/usr/bin/env python3
"""Production fixed-profile codec versus the independent, test-only L2 reference."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signing_reference as reference

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--codec', required=True)
parser.add_argument('--fixture', type=Path, required=True)
ARGS = parser.parse_args()
FIXTURE = json.loads(ARGS.fixture.read_text())


class SignatureCodecReferenceTest(unittest.TestCase):
    comparisons = 0

    def compare(self, request):
        # L2 constructs S, both transactions and preimages independently, using
        # only Python integers/hashlib. It imports no generator/SDK/production.
        expected = reference.virtual_profile(request)
        process = subprocess.run([ARGS.codec, '--derive', expected['request'].hex()],
                                 text=True, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        actual = json.loads(process.stdout)
        fields = {'h': request['claims'][0]['program'], 'd': expected['d'].hex(),
                  'application_message_ascii': expected['message'].decode('ascii'),
                  'application_message_hex': expected['message'].hex(),
                  'application_message_hash': expected['m'].hex(),
                  'selected_script_pubkey': expected['script'].hex(),
                  'script_code': reference.script_for(1, bytes.fromhex(request['claims'][0]['program'])).hex(),
                  'to_spend_hex': expected['parent'].hex(),
                  'to_spend_txid_raw': expected['parent_id'].hex(),
                  'to_spend_txid_display': expected['parent_id'][::-1].hex(),
                  'to_sign_input_outpoint_wire': expected['tx']['inputs'][0]['outpoint'].hex(),
                  'to_sign_unsigned_hex': expected['unsigned'].hex(),
                  'sighash_preimage_hex': expected['preimage'].hex(), 'z': expected['z'].hex()}
        for name, value in fields.items():
            self.assertEqual(actual[name], value, name)
        parent = reference.parse_transaction(bytes.fromhex(actual['to_spend_hex']))
        child = reference.parse_transaction(bytes.fromhex(actual['to_sign_unsigned_hex']))
        self.assertEqual((parent['version'], parent['locktime'], child['version'], child['locktime']), (0, 0, 0, 0))
        self.assertEqual(parent['inputs'][0]['outpoint'], bytes(32) + b'\xff' * 4)
        self.assertEqual(parent['inputs'][0]['script'], b'\x00\x20' + expected['m'])
        self.assertEqual(child['inputs'][0]['outpoint'], expected['parent_id'] + bytes(4))
        self.assertEqual(child['outputs'], [{'amount': 0, 'script': b'\x6a'}])
        self.assertEqual(parent['outputs'][0]['amount'], 0)
        self.assertEqual((parent['inputs'][0]['sequence'], child['inputs'][0]['sequence']), (0, 0))
        type(self).comparisons += 1
        return actual, expected

    def test_frozen_profiles(self):
        for vector in FIXTURE['vectors']:
            with self.subTest(profile=vector['name']):
                actual, expected = self.compare(vector['request'])
                self.assertEqual(expected['request'].hex(), vector['request_hex'])
                self.assertEqual(actual['z'], vector['z'])

    def test_committed_field_mutations(self):
        for vector in FIXTURE['vectors']:
            base = vector['request']
            variants = []

            def change(name, mutate):
                request = copy.deepcopy(base)
                mutate(request)
                variants.append((name, request))

            change('network', lambda r: r.update(network=(r['network'] + 1) % 5))
            change('verifier', lambda r: r.update(verifier='auditor.example/\u6771\u4eac'))
            change('purpose', lambda r: r.update(purpose='proof-of-control'))
            change('nonce', lambda r: r.update(nonce='ff' + r['nonce'][2:]))
            change('message commitment', lambda r: r.update(bip322_message_hash='01' + r['bip322_message_hash'][2:]))
            change('not before', lambda r: r.update(not_before=r['not_before'] + 1))
            change('expiry', lambda r: r.update(expires_at=r['expires_at'] + 1))
            change('selected kind', lambda r: r.update(signing_kind=r['signing_kind'] ^ 1))
            change('claim txid', lambda r: r['claims'][0].update(txid_display='01' + r['claims'][0]['txid_display'][2:]))
            change('claim vout', lambda r: r['claims'][0].update(vout=r['claims'][0]['vout'] + 1))
            change('claim amount', lambda r: r['claims'][0].update(amount_sats=r['claims'][0]['amount_sats'] + 1))
            index = 0 if base['signing_kind'] == 1 else 1
            change('claim kind', lambda r: r['claims'][index].update(script_kind=r['claims'][index]['script_kind'] ^ 1))
            change('common hash', lambda r: [c.update(program='00' + c['program'][2:]) for c in r['claims']])
            change('snapshot presence', lambda r: r.update(snapshot=None if r['snapshot'] else {
                'hash_display': '02' * 32, 'height': 0x01020304}))
            if base['snapshot']:
                change('snapshot hash', lambda r: r['snapshot'].update(hash_display='01' + r['snapshot']['hash_display'][2:]))
                change('snapshot height', lambda r: r['snapshot'].update(height=0x01020304))
            for name, request in variants:
                with self.subTest(profile=vector['name'], field=name):
                    actual, _ = self.compare(request)
                    self.assertNotEqual(actual['d'], vector['d'])
                    self.assertNotEqual(actual['z'], vector['z'])

    def test_networks_and_largest_claim_sets(self):
        for vector in FIXTURE['vectors']:
            for network in range(5):
                request = copy.deepcopy(vector['request'])
                request['network'] = network
                request['claims'] = [dict(request['claims'][0], txid_display=f'{i + 1:064x}',
                                          vout=0xffffffff - i, amount_sats=i + 1,
                                          script_kind=i % 2) for i in range(16)]
                request['claims'][-1]['amount_sats'] = 2100000000000000 - sum(c['amount_sats'] for c in request['claims'][:-1])
                with self.subTest(profile=vector['name'], network=network):
                    self.compare(request)

    def test_wrong_endian_scriptcode_amount_and_compactsize_controls(self):
        for vector in FIXTURE['vectors']:
            actual, expected = self.compare(vector['request'])
            preimage = expected['preimage']
            script_offset = 41 if vector['request']['signing_kind'] == 1 else 104
            self.assertEqual(preimage[script_offset], 25)
            # This API consumes no raw transaction/preimage. These deliberately
            # wrong independent constructions distinguish common encoder bugs;
            # receipt parsing/nonminimal CompactSize rejection belongs to L4.3.
            controls = {
                'sighash big endian': preimage[:-4] + b'\x00\x00\x00\x01',
                'nonminimal CompactSize': preimage[:script_offset] + b'\xfd\x19\x00' + preimage[script_offset + 1:],
                'wrong scriptCode length': preimage[:script_offset] + b'\x18' + preimage[script_offset + 1:],
            }
            reversed_tx = copy.deepcopy(expected['tx'])
            reversed_tx['inputs'][0]['outpoint'] = expected['parent_id'][::-1] + bytes(4)
            program = bytes.fromhex(vector['request']['claims'][0]['program'])
            controls['display txid in wire input'] = reference.digest_preimage(reversed_tx, vector['request']['signing_kind'], program)
            if vector['request']['signing_kind'] == 0:
                controls['real amount instead of synthetic zero'] = reference.digest_preimage(
                    expected['tx'], 0, program, amount=vector['request']['claims'][0]['amount_sats'])
                controls['witness program as scriptCode'] = preimage[:104] + reference.varbytes(expected['script']) + preimage[130:]
                self.assertEqual(preimage[130:138], bytes(8))
            for name, wrong_preimage in controls.items():
                with self.subTest(profile=vector['name'], wrong=name):
                    wrong_digest = hashlib.sha256(hashlib.sha256(wrong_preimage).digest()).hexdigest()
                    self.assertNotEqual(wrong_digest, actual['z'])
                    self.assertNotEqual(wrong_preimage.hex(), actual['sighash_preimage_hex'])
            self.assertNotEqual(bytes.fromhex(actual['z'])[::-1].hex(), actual['z'])

    def test_unsupported_and_malformed_requests_do_not_derive(self):
        for vector in FIXTURE['vectors']:
            raw = bytes.fromhex(vector['request_hex'])
            for offset, value, expected_code, reason in [
                    (4, 4, 66, 'unsupported'), (6, 2, 66, 'unsupported'),
                    (8, 2, 66, 'unsupported'), (9, 2, 66, 'unsupported'),
                    (6, 0, 65, 'malformed_statement')]:
                changed = bytearray(raw)
                changed[offset] = value
                result = subprocess.run([ARGS.codec, '--derive', changed.hex()],
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected_code)
                self.assertEqual(json.loads(result.stdout), {'error': reason})

    @classmethod
    def tearDownClass(cls):
        print(f'{cls.comparisons} independently constructed requests matched production', flush=True)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
