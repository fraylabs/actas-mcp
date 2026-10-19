import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export async function helper(values){
 return new Promise((resolve,reject)=>{
  const env=Object.fromEntries(['PATH','HOME','TMPDIR','SYSTEMROOT'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
  const child=fork(fileURLToPath(new URL('./credential-helper.mjs',import.meta.url)),[],{env,detached:true,stdio:['ignore','ignore','ignore','ipc']});
  const timer=setTimeout(()=>{child.kill();reject(new Error('helper'))},10000);
  child.once('error',()=>{clearTimeout(timer);reject(new Error('helper'))});
  child.once('message',data=>{clearTimeout(timer);child.unref();resolve(data.url)});
  child.send({values});
 });
}
