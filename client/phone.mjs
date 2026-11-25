import {identityRequest,readIdentityConnection} from './identity.mjs';

// Phones this connection may use and the texts each has passed on. Shows only what GET /phones and
// GET /phones/:id/messages already return to the credential. The number is the one on record: a person
// typed it when the phone was added, and the phone app does not report its own.
export const phoneHelp=`Phones
  actas phone                                      Phones this connection may use: number on record, connected or not, last heard from
  actas phone texts [<phone-id>] [--since <time>]  Latest texts: sender, time sent, time ActAs got it, code
  actas phone check [<phone-id>] < number.txt      Does a number match the number on record? Answers match or no match
The number on record is what a person typed when the phone was added; the phone does
not report its own number. A text sent to that number that arrives
is the proof that the number is right.
Connected means the ActAs Phone app is paired with that phone. The phone id may be left
out when the connection has one phone. Texts are kept 7 days. Listing phones needs the
"See names" permission. Reading texts needs "Read SMS codes"; without "See names", name
the phone id. A text's words appear only with "Read forwarded SMS".
`;
const DOCS='https://actas.dev/docs#phone-forwarding';
const PAIR=`A person signed in to the workspace opens Phones, chooses Pair phone and scans the code with the ActAs Phone app on a dedicated Android phone, then turns forwarding on in the app. Guide: ${DOCS}`;
const NUMBER_NOTE='The number on record is what a person typed when the phone was added; the phone does not report its own number. A text sent to that number that arrives is the proof that it is right.';
// Country calling codes are prefix-free: 1 and 7 stand alone, these have two digits, the rest three.
const TWO=new Set('20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98'.split(' '));
export const callingCode=number=>/^\+[1-9]\d{6,14}$/.test(number??'')?'+'+(number[1]==='1'||number[1]==='7'?number[1]:TWO.has(number.slice(1,3))?number.slice(1,3):number.slice(1,4)):null;
const iso=ms=>Number.isFinite(ms)&&ms>0?new Date(ms).toISOString():null;
const show=phone=>({id:phone.id,label:phone.label,numberOnRecord:phone.number||null,countryCode:callingCode(phone.number),country:phone.country||null,
 connected:Boolean(phone.forwarding),device:phone.forwarding?.deviceName??null,pairedAt:iso(phone.forwarding?.pairedAt),lastHeardAt:iso(phone.forwarding?.lastSeenAt),
 ...(phone.forwarding?{}:{note:'No phone app is paired with this phone, so no text can arrive. '+PAIR})});
// Listing phones needs "See names" (resources:read). A connection with only "Read SMS codes" can still read
// a phone's texts by its id, which is all the texts route asks for.
const NO_LIST='This connection may not list phones: it lacks the "See names" permission (resources:read). If it holds "Read SMS codes" for a phone it can still read that phone\'s texts by id: actas phone texts <phone-id>. The workspace owner can find the id on the Phones page, or add "See names" to this connection.';
async function list(connection){
 let phones;
 try{phones=await identityRequest(connection,'/phones');}
 catch(error){if(/resources:read/.test(error.actasRefusal??''))throw Object.assign(Error(NO_LIST),{noList:true});throw error;}
 if(!Array.isArray(phones))throw Error('Invalid ActAs response.');
 return phones;
}
async function pick(connection,id,texts=false){
 let phones;
 try{phones=await list(connection);}
 catch(error){if(texts&&id&&error.noList)return {id,unlisted:true};throw error;}
 if(id)return phones.find(p=>p.id===id)??{id,unlisted:true};
 if(!phones.length)throw Error('This connection can see no phone. If the workspace has one, ask its owner to give this connection access to it. To add one: '+PAIR);
 if(phones.length>1)throw Error('This connection can see '+phones.length+' phones. Name one: run actas phone for their ids.');
 return phones[0];
}
async function stdin(){let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>200)throw Error('Send one phone number on stdin.');}return input;}

export async function runPhoneCommand(args){
 const [command,action,...rest]=args;
 if(command!=='phone')return false;
 try{
  const connection=await readIdentityConnection();
  let result;
  if(action===undefined){
   const phones=await list(connection);
   result=phones.length?{phones:phones.map(show),note:NUMBER_NOTE}
    :{phones:[],message:'This connection can see no phone. If the workspace has one, ask its owner to give this connection access to it. To add one: '+PAIR};
  }else if(action==='texts'){
   const id=rest[0]&&!rest[0].startsWith('--')?rest.shift():null;
   if(rest.length&&(rest.length!==2||rest[0]!=='--since'))throw Error('Use actas phone texts [<phone-id>] [--since <time>].');
   const since=rest.length?Date.parse(rest[1]):0;
   if(!Number.isFinite(since)||since<0)throw Error('Give --since a time such as 2026-11-12T05:00:00Z.');
   const phone=await pick(connection,id,true);
   const texts=await identityRequest(connection,'/phones/'+encodeURIComponent(phone.id)+'/messages'+(since?'?since='+since:''));
   if(!Array.isArray(texts))throw Error('Invalid ActAs response.');
   const connected=phone.forwarding===undefined?undefined:Boolean(phone.forwarding);
   result={phone:{id:phone.id,...(phone.label?{label:phone.label}:{}),...(connected===undefined?{}:{connected,lastHeardAt:iso(phone.forwarding?.lastSeenAt)})},
    // sentAt is the text's own time as the phone reports it; reachedActasAt is when ActAs stored it.
    texts:texts.map(t=>({from:t.from,sentAt:iso(t.receivedAt),reachedActasAt:iso(t.storedAt),secondsToReachActas:Number.isFinite(t.storedAt)&&Number.isFinite(t.receivedAt)?Math.round((t.storedAt-t.receivedAt)/100)/10:null,code:t.code??null,...('body' in t?{body:t.body,untrusted:true}:{})})),
    ...(texts.length?{}:{message:connected===false?'No phone app is paired with this phone, so no text can arrive. '+PAIR
     :'No text from this phone '+(since?'since '+new Date(since).toISOString():'in the last 7 days')+'. A text that reaches the phone reaches ActAs within seconds. If one was expected, it was not sent to this phone: check the number and country code on the sender\'s form against the number on record (actas phone).'})};
  }else if(action==='check'&&rest.length<=1){
   const phone=await pick(connection,rest[0]);
   if(phone.unlisted)throw Error('This connection cannot see that phone. Run actas phone for the ones it can.');
   if(!phone.number)throw Error('No number is on record for this phone.');
   const raw=(await stdin()).trim().replace(/[\s().-]/g,'');
   if(!/^\+?\d{4,15}$/.test(raw))throw Error('Send one phone number on stdin, digits with an optional leading +.');
   const given=raw.replace('+',''),record=phone.number.replace('+',''),match=given===record;
   // Never echoes either number: the answer is match or no match, plus the record's country code.
   result={phone:{id:phone.id,label:phone.label},match,countryCodeOnRecord:callingCode(phone.number),
    ...(!match&&!raw.startsWith('+')&&record.endsWith(given)&&record.length-given.length<=3?{note:'The digits match the number on record without its country code.'}:{})};
  }else throw Error('Use actas phone, actas phone texts [<phone-id>] [--since <time>] or actas phone check [<phone-id>].');
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
 }catch(error){process.stderr.write(JSON.stringify({status:'failed',message:error.message})+'\n');process.exitCode=1;}
 return true;
}
