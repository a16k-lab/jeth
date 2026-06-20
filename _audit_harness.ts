import { compile } from './src/compile.js';
import { compileSolidity, readSlot } from './test/_solidity.js';
import { Harness, pad32 } from './src/evm.js';
import { functionSelector } from './src/selectors.js';
import { Address } from '@ethereumjs/util';
export const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
export const sel = (s: string) => functionSelector(s);
export const A = new Address(Buffer.from('11'.repeat(20), 'hex'));
export function jethCompiles(src: string){ try { compile(src,{fileName:'C.jeth'}); return {ok:true} as any; } catch(e:any){ const d=e?.diagnostics?.[0]; return {ok:false,code:d?.code,msg:d?.message??String(e?.message??e)}; } }
export function solcCompiles(src: string){ try { compileSolidity(SPDX+src,'C'); return {ok:true} as any; } catch(e:any){ return {ok:false,msg:String(e?.message??e).split('\n').slice(1,3).join(' ').slice(0,180)}; } }
export function acceptParity(j: string, s: string, l: string){ const a=jethCompiles(j),b=solcCompiles(s); if(a.ok&&!b.ok) return `${l}: JETH ACCEPTS solc REJECTS (${b.msg})`; if(!a.ok&&b.ok) return `${l}: JETH REJECTS (${a.code}: ${a.msg}) solc ACCEPTS`; return `${l}: parity (both ${a.ok?'accept':'reject'})`; }
export async function runDiff(label: string, jeth: string, sol: string, calls: {sig:string;args?:string}[], slots: bigint[] = []){
  const out: string[] = []; const jr=jethCompiles(jeth),sr=solcCompiles(sol);
  if(!jr.ok||!sr.ok){ if(jr.ok&&!sr.ok)out.push(`${label}: JETH ACCEPTS solc REJECTS (${sr.msg})`); else if(!jr.ok&&sr.ok)out.push(`${label}: JETH REJECTS (${jr.code} ${jr.msg}) solc ACCEPTS`); return out; }
  const jc=compile(jeth,{fileName:'C.jeth'}); const sc=compileSolidity(SPDX+sol,'C');
  const hj=await Harness.create(),hs=await Harness.create(); await hj.fund(A,10n**20n); await hs.fund(A,10n**20n);
  const aj=await hj.deploy(jc.creationBytecode); const as=await hs.deploy(sc.creation);
  for(const c of calls){ const d='0x'+sel(c.sig)+(c.args??''); const rj=await hj.call(aj,d,{caller:A}); const rs=await hs.call(as,d,{caller:A}); const t=`${label}: ${c.sig}`;
    if(rj.success!==rs.success)out.push(`${t} success J=${rj.success} S=${rs.success} Jret=${rj.returnHex} Sret=${rs.returnHex}`);
    else if(rj.returnHex!==rs.returnHex)out.push(`${t} returndata J=${rj.returnHex} S=${rs.returnHex}`);
    else if(JSON.stringify(rj.logs)!==JSON.stringify(rs.logs))out.push(`${t} logs J=${JSON.stringify(rj.logs)} S=${JSON.stringify(rs.logs)}`); }
  for(const s of slots){ const vj=await readSlot(hj,aj,s),vs=await readSlot(hs,as,s); if(vj!==vs)out.push(`${label}: slot ${s} J=${vj} S=${vs}`); }
  return out;
}
