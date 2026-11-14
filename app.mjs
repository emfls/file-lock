import {encryptFile,decryptFile,MAX_FILE_BYTES,MAX_CONTAINER_BYTES} from './crypto.mjs';
const $=id=>document.getElementById(id);
const form=$('tool'), controls=$('controls'), file=$('file'), pass=$('password'), confirm=$('confirm'), status=$('status'), download=$('download');
let busy=false, resultURL=null, generation=0;
const mode=()=>form.elements.mode.value;
function clearResult(){ if(resultURL) URL.revokeObjectURL(resultURL); resultURL=null; download.removeAttribute('href'); download.removeAttribute('download'); download.hidden=true; }
function clearSecrets(){pass.value='';confirm.value='';}
function updateMode(){clearResult();clearSecrets();const encrypt=mode()==='encrypt';$('confirmation').hidden=!encrypt;confirm.required=encrypt;pass.autocomplete=encrypt?'new-password':'off';$('run').textContent=encrypt?'암호화 시작':'복호화 시작';$('file-help').textContent=encrypt?'원본 최대 25 MiB. 폴더는 먼저 ZIP 파일로 묶어 주세요.':'이 도구로 만든 .dlock 파일을 선택하세요. 암호화 시 사용한 비밀번호가 필요합니다.';status.textContent='파일을 선택해 주세요.';file.value='';}
form.addEventListener('change',e=>{if(e.target.name==='mode')updateMode();else clearResult();});
form.addEventListener('input',()=>{if(!busy)clearResult();});
$('clear').addEventListener('click',()=>{if(busy)return;clearResult();form.reset();updateMode();file.focus();});
form.addEventListener('submit',async e=>{
 e.preventDefault();if(busy)return;clearResult();
 const selected=file.files[0],creating=mode()==='encrypt';
 if(!selected){status.textContent='파일을 선택해 주세요.';return;}
 if(selected.size>(creating?MAX_FILE_BYTES:MAX_CONTAINER_BYTES)){status.textContent='지원 크기를 초과했습니다. 원본 기준 최대 25 MiB입니다.';return;}
 if(creating&&pass.value!==confirm.value){status.textContent='두 비밀번호가 다릅니다.';confirm.focus();return;}
 const taskGeneration=++generation;
 busy=true;controls.disabled=true;$('clear').disabled=true;status.textContent='브라우저 안에서 처리 중입니다. 페이지를 닫지 마세요…';
 try{
   let blob,name;
   if(creating){blob=await encryptFile(selected,pass.value);name='locked-file.dlock';}
   else {const output=await decryptFile(selected,pass.value);blob=output.blob;name=output.name;}
   if(taskGeneration!==generation)return;
   resultURL=URL.createObjectURL(blob);download.href=resultURL;download.download=name;download.textContent=creating?'암호화 파일 다운로드':'원본 파일 다운로드';download.hidden=false;
   status.textContent=creating?'암호화 완료. 다운로드 후 복호화가 되는지 확인하세요. 원본은 자동 삭제하지 않습니다.':'복호화 완료. 다운로드 버튼으로 저장하세요. 파일을 자동 실행하지 않습니다.';
 }catch(error){if(taskGeneration!==generation)return;status.textContent=error instanceof Error?error.message:'처리하지 못했습니다. 파일과 브라우저를 확인하세요.';}
 finally{clearSecrets();file.value='';busy=false;controls.disabled=false;$('clear').disabled=false;}
});
window.addEventListener('pagehide',()=>{generation++;clearResult();clearSecrets();file.value='';status.textContent='페이지를 떠나 결과를 폐기했습니다. 파일을 다시 선택해 주세요.';});
if(!globalThis.isSecureContext||!globalThis.crypto?.subtle){controls.disabled=true;status.textContent='HTTPS 환경과 Web Crypto 지원 브라우저가 필요합니다.';}
