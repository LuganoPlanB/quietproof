#!/usr/bin/env python3
"""Opt-in integration tests against an explicitly supplied installed Sparrow image."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import sparrow_signer

CONFIG = None


class SparrowSignerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='sparrow-signer-tests-')
        cls.root = Path(cls.temp.name)
        cls.base = [sys.executable, str(Path(__file__).with_name('sparrow_signer.py')),
                    '--sparrow', str(CONFIG.sparrow.resolve()), '--jdk', str(CONFIG.jdk.resolve()),
                    '--cache', str(CONFIG.cache.resolve()), '--network', 'signet']
        cls.wallets = {}
        cls.addresses = {}
        for kind in ['p2wpkh', 'p2pkh', 'p2tr']:
            wallet = cls.root / kind
            response = cls.invoke('create', '--wallet-dir', wallet, '--script-kind', kind)
            cls.wallets[kind] = wallet
            cls.addresses[kind] = json.loads(response.stdout)['address']

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def invoke(cls, *args, success=True):
        result = subprocess.run(cls.base + list(map(str, args)), capture_output=True, timeout=120)
        if success and result.returncode != 0:
            raise AssertionError('helper failed: ' + result.stderr.decode())
        if not success and result.returncode == 0:
            raise AssertionError('helper accepted invalid operation')
        return result

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=self.root))
        self.message = self.case / 'message'
        self.message.write_bytes('line one\nUTF-8: é 日本語\n'.encode())

    def args_for(self, kind='p2wpkh', format='bip322-simple'):
        return ['--wallet-dir', self.wallets[kind], '--script-kind', kind,
                '--address', self.addresses[kind], '--format', format, '--message', self.message]

    def sign(self, kind='p2wpkh', format='bip322-simple', name='signature.json'):
        path = self.case / name
        result = self.invoke('sign', *self.args_for(kind, format), '--output', path)
        self.assertNotIn('signature', json.loads(result.stdout))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return path, json.loads(path.read_text())

    def test_utf8_newline_exactness_and_repeat(self):
        path, first = self.sign()
        _, second = self.sign(name='repeat.json')
        self.assertEqual(first['signature'], second['signature'])
        self.invoke('verify', *self.args_for(), '--signature', path)
        # Independently decode the Simple witness, without implementing signing.
        self.assertTrue(first['signature'].startswith('smp'))
        witness = base64.b64decode(first['signature'][3:], validate=True)
        self.assertEqual(witness[0], 2)
        size = witness[1]
        self.assertEqual(witness[2], 0x30)  # DER sequence
        self.assertEqual(witness[1 + size], 1)  # SIGHASH_ALL
        self.assertEqual(witness[2 + size], 33)
        self.assertEqual(len(witness), 3 + size + 33)
        self.message.write_bytes(self.message.read_bytes().rstrip(b'\n'))
        self.invoke('verify', *self.args_for(), '--signature', path, success=False)

    def test_wrong_address_and_message_rejected(self):
        path, _ = self.sign()
        self.invoke('verify', *self.args_for(), '--signature', path,
                    '--address', self.addresses['p2tr'], success=False)
        self.message.write_bytes(b'different')
        self.invoke('verify', *self.args_for(), '--signature', path, success=False)

    def test_compact_formats_are_distinct_from_bip322(self):
        for kind in ['p2wpkh', 'p2pkh']:
            for format in ['standard', 'electrum', 'bip137']:
                with self.subTest(kind=kind, format=format):
                    path, signed = self.sign(kind, format, kind + format + '.json')
                    compact = base64.b64decode(signed['signature'], validate=True)
                    self.assertEqual(len(compact), 65)
                    low = 39 if kind == 'p2wpkh' and format == 'bip137' else 31
                    self.assertTrue(low <= compact[0] <= low + 3)
                    self.invoke('verify', *self.args_for(kind, format), '--signature', path)

    def test_taproot_simple_is_produced(self):
        path, signed = self.sign('p2tr')
        witness = base64.b64decode(signed['signature'][3:], validate=True)
        self.assertEqual(witness[0], 1)
        self.assertIn(witness[1], [64, 65])
        self.assertEqual(len(witness), witness[1] + 2)
        self.invoke('verify', *self.args_for('p2tr'), '--signature', path)

    def test_unsupported_formats_reject_without_output(self):
        for kind, format in [('p2pkh', 'bip322-simple'), ('p2wpkh', 'bip322-full'),
                             ('p2tr', 'standard'), ('p2tr', 'bip137')]:
            with self.subTest(kind=kind, format=format):
                out = self.case / (kind + format)
                result = self.invoke('sign', *self.args_for(kind, format), '--output', out, success=False)
                self.assertFalse(out.exists())
                self.assertNotIn(b'private', result.stderr.lower())
                self.assertEqual(result.stdout, b'')

    def test_reload_reproduces_owned_address(self):
        for kind in self.wallets:
            result = self.invoke('address', '--wallet-dir', self.wallets[kind], '--script-kind', kind)
            owned = json.loads(result.stdout)
            self.assertEqual(owned['address'], self.addresses[kind])
            purpose = {'p2wpkh': 84, 'p2pkh': 44, 'p2tr': 86}[kind]
            self.assertEqual(owned['derivation'], f"m/{purpose}'/1'/0'/0/0")

    def test_explicit_owned_change_signs_and_preserves_original(self):
        wallet = self.wallets['p2pkh']
        before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in wallet.iterdir()}
        response = self.invoke('address','--wallet-dir',wallet,'--script-kind','p2pkh',
                               '--key-path','m/1/0')
        change = json.loads(response.stdout)
        self.assertEqual(change['keyPath'],'m/1/0')
        self.assertEqual(change['derivation'],"m/44'/1'/0'/1/0")
        self.assertNotEqual(change['address'],self.addresses['p2pkh'])
        common = self.args_for('p2pkh','standard')+['--address',change['address'],'--key-path','m/1/0']
        output = self.case/'change-signature.json'
        self.invoke('sign',*common,'--output',output)
        self.invoke('verify',*common,'--signature',output)
        self.invoke('verify',*common,'--key-path','m/0/0','--signature',output,success=False)
        self.invoke('sign',*common,'--address',self.addresses['p2pkh'],
                    '--output',self.case/'wrong-owner.json',success=False)
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in wallet.iterdir()})

    def test_wrong_or_unsupported_key_path_rejected(self):
        for path in ['m/1/1','m/2/0','m/0/0/0','m/44h/1h/0h/1/0','../m/1/0','']:
            with self.subTest(path=path):
                output=self.case/'invalid-path.json'
                self.invoke('sign',*self.args_for('p2pkh','standard'),'--key-path',path,
                            '--output',output,success=False)
                self.assertFalse(output.exists())
        self.invoke('create','--wallet-dir',self.case/'invalid-create','--key-path','m/1/0',success=False)
        self.assertFalse((self.case/'invalid-create').exists())

    def test_used_receive_address_remains_signable_after_history_reload(self):
        wallet = self.case / 'history-wallet'
        created = json.loads(self.invoke('create', '--wallet-dir', wallet).stdout)
        # Persist a real bundled WalletNode transaction output, then reload the
        # Sparrow database and establish that its fresh-address API advances.
        # This fixture never touches the separately funded qualification wallets.
        fixture = self.case / 'MarkUsed.java'
        fixture.write_text('''
import java.io.File;
import java.util.*;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.io.Storage;
public class MarkUsed {
 public static void main(String[] args) throws Exception {
  Network.set(Network.SIGNET);
  Storage storage=new Storage(new File(args[0],"P2WPKH.mv.db"));
  Wallet wallet=storage.loadUnencryptedWallet().getWallet();
  storage.restorePublicKeysFromSeed(wallet,null);
  WalletNode zero=wallet.getNode(KeyPurpose.RECEIVE).getChildren().stream()
    .filter(node -> node.getIndex()==0).findFirst().orElseThrow();
  zero.setTransactionOutputs(new TreeSet<>(List.of(new BlockTransactionHashIndex(
    Sha256Hash.wrap("01".repeat(32)),1,new Date(1),null,0,10000))));
  storage.saveWallet(wallet);
  storage.closeAndWait();
  Storage reloaded=new Storage(new File(args[0],"P2WPKH.mv.db"));
  Wallet restored=reloaded.loadUnencryptedWallet().getWallet();
  reloaded.restorePublicKeysFromSeed(restored,null);
  if(restored.getNode(KeyPurpose.RECEIVE).getHighestUsedIndex()!=0
      || restored.getFreshNode(KeyPurpose.RECEIVE).getIndex()!=1)
    throw new IllegalStateException("fixture did not persist used address history");
  reloaded.closeAndWait();
  System.out.println("FRESH_INDEX=1");
  System.exit(0);
 }
}
''')
        java, classpath, _ = sparrow_signer.prepare(argparse.Namespace(
            sparrow=CONFIG.sparrow, jdk=CONFIG.jdk, cache=CONFIG.cache.resolve()))
        result = subprocess.run([str(java / 'java'), '--enable-native-access=ALL-UNNAMED',
                                 '-Duser.home=' + str(self.case), '-cp', classpath,
                                 str(fixture), str(wallet)], capture_output=True, timeout=60,
                                umask=0o077)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'FRESH_INDEX=1', result.stdout)
        common = self.args_for() + ['--wallet-dir', wallet, '--address', created['address']]
        signature = self.case / 'used-address-signature.json'
        signed = json.loads(self.invoke('sign', *common, '--output', signature).stdout)
        self.assertEqual(signed['address'], created['address'])
        self.assertEqual(signed['derivation'], "m/84'/1'/0'/0/0")
        self.invoke('verify', *common, '--signature', signature)

    def test_invalid_encoding_and_oversize_reject(self):
        for data in [b'\xff', b'x' * (1024 * 1024 + 1)]:
            self.message.write_bytes(data)
            self.invoke('sign', *self.args_for(), '--output', self.case / 'invalid.json', success=False)

    def test_empty_bom_nul_and_whitespace_bytes(self):
        for index, data in enumerate([b'', b'\xef\xbb\xbfhello\x00world', b'  trailing \n\n']):
            with self.subTest(data=index):
                self.message.write_bytes(data)
                path, _ = self.sign(name=str(index) + '.json')
                self.invoke('verify', *self.args_for(), '--signature', path)

    def test_signature_metadata_and_permissions_reject(self):
        path, signed = self.sign()
        signed['network'] = 'testnet4'
        path.write_text(json.dumps(signed))
        self.invoke('verify', *self.args_for(), '--signature', path, success=False)
        path.chmod(0o644)
        self.invoke('verify', *self.args_for(), '--signature', path, success=False)

    def test_exclusive_output_and_symlinks(self):
        path, _ = self.sign()
        original = path.read_bytes()
        self.invoke('sign', *self.args_for(), '--output', path, success=False)
        self.assertEqual(path.read_bytes(), original)
        link = self.case / 'link'
        link.symlink_to(self.message)
        self.invoke('sign', *self.args_for(), '--message', link, '--output', self.case / 'unused', success=False)

    def test_unmarked_wallet_and_mainnet_reject(self):
        self.invoke('address', '--wallet-dir', self.case, success=False)
        self.invoke('address', '--wallet-dir', self.wallets['p2wpkh'], '--network', 'mainnet', success=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sparrow', type=Path, required=True)
    parser.add_argument('--jdk', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    CONFIG, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0]] + remaining)
