// Trusted consumers may parse outside data for display/exact challenge matching.
// Never return this decoded object directly through an agent-facing mail tool.
export function mailContent(message){
 if(message?.untrusted!==true)return message;
 if(typeof message.text!=='string')return;
 const match=/^<(untrusted-email-[a-f0-9]{16})>\nOutside email\.[^\n]*\nSender check: [^\n]*\nMetadata: ([^\n]*)\n\n([\s\S]*)\n<\/\1>$/.exec(message.text);
 if(!match)return;
 try{const metadata=JSON.parse(match[2]);if(!metadata||typeof metadata!=='object'||Array.isArray(metadata))return;return {...metadata,text:match[3]};}catch{return;}
}
