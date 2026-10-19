// Ephemeral loopback delivery UI used by the calling agent's documented browser.
import {createServer} from 'node:http';
import {randomBytes,timingSafeEqual} from 'node:crypto';
process.once('message',({values})=>{
 const token=randomBytes(32).toString('hex');let origin;
 const page=`<!doctype html><html><head><title>ActAs local credential delivery</title><meta name="viewport" content="width=device-width"></head><body><h1>ActAs credential delivery</h1><p>Assigned account. Load each field for transfer into its authorised signup, verification or login form. Values are masked. Use Copy loaded value to transfer through your authorised browser clipboard, then clear the helper and clipboard.</p><button data-field="code">Load verification code</button><button data-field="username">Load username</button><button data-field="verificationUrl">Load verification link</button><button data-field="email">Load email</button><button data-field="password">Load password</button><button data-field="operator">Load operator key</button><label>Credential delivery<input id="delivery" type="password" readonly autocomplete="off" spellcheck="false"></label><button id="copy">Copy loaded value</button><button id="clear">Clear loaded value</button><button id="clear-clipboard">Clear clipboard</button><p id="status"></p><script>document.querySelectorAll('button[data-field]').forEach(b=>b.addEventListener('click',async()=>{const r=await fetch('/copy/'+b.dataset.field,{method:'POST'});if(!r.ok){document.getElementById('status').textContent='Delivery unavailable';return}document.getElementById('delivery').value=await r.text();document.getElementById('status').textContent=b.textContent.replace('Load','Loaded')}));document.getElementById('copy').onclick=async()=>{try{await navigator.clipboard.writeText(document.getElementById('delivery').value);document.getElementById('status').textContent='Copied loaded value'}catch{document.getElementById('status').textContent='Clipboard unavailable'}};document.getElementById('clear-clipboard').onclick=async()=>{try{await navigator.clipboard.writeText('');document.getElementById('status').textContent='Clipboard cleared'}catch{document.getElementById('status').textContent='Clipboard unavailable'}};document.getElementById('clear').onclick=()=>{document.getElementById('delivery').value='';document.getElementById('status').textContent='Cleared'};</script></body></html>`;
 const server=createServer((req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('X-Content-Type-Options','nosniff');
  if(req.headers.host!==new URL(origin).host){res.writeHead(403);return res.end();}
  if(req.method==='GET'&&req.url==='/health'){res.writeHead(200);return res.end('ready-v3');}
  if(req.method==='GET'&&req.url==='/'){
   res.setHeader('Content-Type','text/html');res.setHeader('Set-Cookie',`delivery=${token}; HttpOnly; SameSite=Strict; Path=/`);
   res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
   return res.end(page);
  }
  const cookie=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('delivery='))?.slice(9)||'';
  if(req.method!=='POST'||req.headers.origin!==origin||Buffer.byteLength(cookie)!==Buffer.byteLength(token)||!timingSafeEqual(Buffer.from(cookie),Buffer.from(token))){res.writeHead(403);return res.end();}
  const field=req.url?.slice('/copy/'.length);
  if(!req.url?.startsWith('/copy/')||!['email','password','operator','code','username','verificationUrl'].includes(field)||typeof values[field]!=='string'){res.writeHead(404);return res.end();}
  res.setHeader('Content-Type','text/plain');res.end(values[field]);
 });
 server.listen(0,'127.0.0.1',()=>{origin=`http://127.0.0.1:${server.address().port}`;process.send({url:origin+'/'});process.disconnect();});
 setTimeout(()=>{server.close();process.exit(0)},300000).unref();
});
