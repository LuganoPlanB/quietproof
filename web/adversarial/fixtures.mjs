// Node-only public fixture composition. Private-key operations stay in the
// existing native CLI; neither this module nor its scalar list ships in the app.
import { workflows, providerResponse } from '../features/request/workflow-fixtures.mjs';
import { fixtures } from '../features/provider/fixtures.mjs';

export function witnessAddress(network, program) {
  const hrp = network === 'mainnet' ? 'bc' : 'tb', alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const data = [0]; let accumulator = 0, bits = 0;
  for (const byte of Buffer.from(program, 'hex')) {
    accumulator = ((accumulator & 0xffff) << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; data.push((accumulator >>> bits) & 31); }
  }
  if (bits) data.push((accumulator << (5 - bits)) & 31);
  const expanded = [...hrp].map(c => c.charCodeAt(0) >>> 5).concat(0, [...hrp].map(c => c.charCodeAt(0) & 31), data, Array(6).fill(0));
  const generators = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; let checksum = 1;
  for (const word of expanded) {
    const top = checksum >>> 25; checksum = ((checksum & 0x1ffffff) << 5) ^ word;
    for (let i=0;i<5;i++) if ((top >>> i) & 1) checksum ^= generators[i];
  }
  checksum ^= 1;
  return hrp + '1' + [...data,...Array.from({length:6},(_,i)=>(checksum >>> (5*(5-i))) & 31)].map(n=>alphabet[n]).join('');
}

export const roundtrips = ['mainnet','signet'].flatMap(network => {
  return workflows.filter(w => w.network === network).map(w => ({ ...w, keyCount: 1 }));
});

export function observationResponse(workflow,url,mode='unspent') {
  const tip='56'.repeat(32), funding=fixtures.block;
  const status={confirmed:true,block_height:100,block_hash:funding,block_time:1600000000};
  if (url.endsWith('/blocks/tip/hash')) return {body:tip};
  if (url.endsWith('/block-height/100')) return {body:funding};
  if (url.endsWith(`/block/${tip}`)) return {json:{id:tip,height:110}};
  if (url.endsWith(`/block/${funding}/status`)) return {json:{in_best_chain:mode!=='reorg'}};
  if (workflow.claims.some(c=>url.endsWith(`/tx/${c.txid}/status`))) return {json:status};
  if (workflow.claims.some(c=>url.endsWith(`/tx/${c.txid}/outspend/${c.vout}`))) return {json:mode==='spent'
    ? {spent:true,txid:'78'.repeat(32),vin:0,status:{confirmed:false}} : {spent:false}};
  return providerResponse(workflow,url);
}
