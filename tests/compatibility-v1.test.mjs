import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {decryptFile as currentDecrypt} from '../crypto.mjs';
import {decryptFile as frozenDecrypt} from '../compatibility/crypto-v1-frozen.mjs';
const base=new URL('./fixtures/v1/',import.meta.url);
const manifest=JSON.parse(readFileSync(new URL('manifest.json',base),'utf8'));
const sha=b=>createHash('sha256').update(b).digest('hex');
test('frozen v1 decoder integrity',()=>assert.equal(sha(readFileSync(new URL('../compatibility/crypto-v1-frozen.mjs',import.meta.url))),manifest.frozen_decoder_sha256));
for(const item of manifest.fixtures){
 const encrypted=readFileSync(new URL(`${item.id}.dlock`,base));
 const original=readFileSync(new URL(`${item.id}.original`,base));
 test(`immutable v1 fixture integrity: ${item.id}`,()=>{assert.equal(sha(encrypted),item.ciphertext_sha256);assert.equal(sha(original),item.plaintext_sha256);assert.equal(encrypted[8],1);assert.equal(encrypted.readUInt32BE(12),600000);});
 for(const [name,decrypt] of [['current',currentDecrypt],['frozen-v1',frozenDecrypt]])test(`${name} restores historical v1 fixture: ${item.id}`,async()=>{const result=await decrypt(new Blob([encrypted]),manifest.password);assert.equal(result.name,item.name);assert.deepEqual(Buffer.from(await result.blob.arrayBuffer()),original);});
 test(`historical v1 wrong password/tamper rejection: ${item.id}`,async()=>{await assert.rejects(currentDecrypt(new Blob([encrypted]),'PUBLIC-wrong-fixture-password'));const bad=Buffer.from(encrypted);bad[bad.length-1]^=1;await assert.rejects(currentDecrypt(new Blob([bad]),manifest.password));});
}
