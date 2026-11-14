// Versioned local file container. This implementation has not had an external security audit.
export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const ITERATIONS = 600000;
export const HEADER_BYTES = 44;
const MAX_META_BYTES = 4096;
export const MAX_CONTAINER_BYTES = MAX_FILE_BYTES + MAX_META_BYTES + 4 + HEADER_BYTES + 16;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
const MAGIC = enc.encode('DOTLOCK!');
function cryptoAPI() {
  if (!globalThis.crypto?.subtle) throw new Error('HTTPS 환경과 Web Crypto를 지원하는 최신 브라우저가 필요합니다.');
  return globalThis.crypto;
}
function passwordBytes(password, creating = false) {
  if (typeof password !== 'string' || !password.length || (creating && [...password].length < 16)) throw new Error(creating ? '새 비밀번호는 16자 이상이어야 합니다.' : '비밀번호를 입력해 주세요.');
  if (creating) {
    const points = [...password];
    const repeated = Array.from({length:8},(_,i)=>i+1).some(n=>points.length%n===0 && points.every((c,i)=>c===points[i%n]));
    if (!password.trim() || new Set(points).size < 5 || repeated || /(.)\1{7}/u.test(password)) throw new Error('반복 문자·공백 위주의 비밀번호는 사용할 수 없습니다. 더 길고 예측하기 어려운 비밀번호를 선택하세요.');
  }
  const bytes = enc.encode(password);
  if (bytes.length > 1024) { bytes.fill(0); throw new Error('비밀번호는 UTF-8 기준 1,024바이트 이하여야 합니다.'); }
  return bytes;
}
async function keyFor(password, salt, creating = false) {
  const bytes = passwordBytes(password, creating);
  try {
    const material = await cryptoAPI().subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await cryptoAPI().subtle.deriveKey({ name:'PBKDF2', salt, iterations:ITERATIONS, hash:'SHA-256' }, material, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
  } finally { bytes.fill(0); }
}
export function safeDownloadName(name) {
  const clean = String(name).replace(/[\\/\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '_').replace(/[. ]+$/g, '');
  return clean && clean !== '.' && clean !== '..' ? clean : 'restored-file';
}
export async function encryptFile(file, password) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_FILE_BYTES) throw new Error('원본 파일은 최대 25 MiB입니다.');
  if (typeof file.name !== 'string' || file.name.length < 1) throw new Error('파일 이름이 필요합니다.');
  const metadata = enc.encode(JSON.stringify({name:file.name}));
  if (metadata.length > MAX_META_BYTES) throw new Error('파일 이름이 너무 깁니다.');
  const api = cryptoAPI();
  const header = new Uint8Array(HEADER_BYTES);
  header.set(MAGIC); header[8]=1; header[9]=1;
  new DataView(header.buffer).setUint32(12, ITERATIONS, false);
  api.getRandomValues(header.subarray(16,32)); api.getRandomValues(header.subarray(32,44));
  const key = await keyFor(password, header.subarray(16,32), true);
  const raw = new Uint8Array(await file.arrayBuffer());
  if (raw.length !== file.size) { raw.fill(0); throw new Error('파일 크기가 변경되었습니다.'); }
  const payload = new Uint8Array(4+metadata.length+raw.length);
  new DataView(payload.buffer).setUint32(0, metadata.length, false);
  payload.set(metadata,4); payload.set(raw,4+metadata.length); raw.fill(0);
  try {
    const encrypted = await api.subtle.encrypt({name:'AES-GCM',iv:header.subarray(32,44),additionalData:header,tagLength:128},key,payload);
    return new Blob([header,encrypted],{type:'application/octet-stream'});
  } finally { payload.fill(0); metadata.fill(0); }
}
export async function decryptFile(file, password) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < HEADER_BYTES+16+4 || file.size > MAX_CONTAINER_BYTES) throw new Error('지원하지 않는 크기이거나 손상된 암호화 파일입니다.');
  const input = new Uint8Array(await file.arrayBuffer());
  if(input.length !== file.size) throw new Error('파일 크기가 변경되었습니다.');
  const header = input.subarray(0,HEADER_BYTES);
  if (!MAGIC.every((v,i)=>header[i]===v) || header[8]!==1 || header[9]!==1 || header[10]!==0 || header[11]!==0 || new DataView(header.buffer,header.byteOffset,header.length).getUint32(12,false)!==ITERATIONS) throw new Error('지원하지 않는 형식·버전이거나 손상된 파일입니다.');
  const key = await keyFor(password,header.subarray(16,32));
  let plaintext;
  try { plaintext = new Uint8Array(await cryptoAPI().subtle.decrypt({name:'AES-GCM',iv:header.subarray(32,44),additionalData:header,tagLength:128},key,input.subarray(HEADER_BYTES))); }
  catch { throw new Error('복호화 실패: 비밀번호가 다르거나 파일이 손상·변조되었습니다.'); }
  try {
    if(plaintext.length<4) throw new Error('손상된 파일 내용입니다.');
    const n = new DataView(plaintext.buffer).getUint32(0,false);
    if(n<1 || n>MAX_META_BYTES || n+4>plaintext.length || plaintext.length-n-4>MAX_FILE_BYTES) throw new Error('손상된 파일 내용입니다.');
    const meta = JSON.parse(dec.decode(plaintext.subarray(4,4+n)));
    if (!meta || typeof meta.name!=='string' || !meta.name.length || Object.keys(meta).length!==1) throw new Error('손상된 파일 정보입니다.');
    return {name:safeDownloadName(meta.name),blob:new Blob([plaintext.subarray(4+n)],{type:'application/octet-stream'})};
  } finally { plaintext.fill(0); }
}
