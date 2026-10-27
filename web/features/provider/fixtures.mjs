// Public generator-key addresses, BIP173 examples; no secrets or live state.
export const fixtures = Object.freeze({
  txid: '12'.repeat(32), block: '34'.repeat(32),
  mainnet: { genesis: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    p2wpkh: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', p2pkh: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH' },
  signet: { genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
    p2wpkh: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', p2pkh: 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r' },
  program: '751e76e8199196d454941c45d1b3a323f1433bd6'
});
export function outputFixture(scriptKind = 'p2wpkh') {
  const status = { confirmed: true, block_height: 100, block_hash: fixtures.block, block_time: 1600000000 };
  const utxos = [{ txid: fixtures.txid, vout: 0, value: 12345, status }];
  const script = scriptKind === 'p2wpkh' ? `0014${fixtures.program}` : `76a914${fixtures.program}88ac`;
  return { utxos, tx: { txid: fixtures.txid, vout: [{ value: 12345, scriptpubkey: script }], status: { ...status } } };
}
