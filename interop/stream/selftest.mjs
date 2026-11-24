import {strict as assert} from 'node:assert';
import {spawn} from 'node:child_process';
import {readFileSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
import {createHash,createPrivateKey,sign,verify,createPublicKey} from 'node:crypto';
import net from 'node:net';
import {startRelay} from './relay.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const b64=b=>Buffer.from(b).toString('base64url');
const hash=b=>createHash('sha256').update(b).digest('base64url');
const keys=JSON.parse(readFileSync(join(root,'spec/fixtures/keys.json'),'utf8')).keys;
const svc=keys.find(k=>k.name==='svc');
const privateKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(svc.seed_hex,'hex')]),format:'der',type:'pkcs8'});
const publicKey=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(svc.public_key,'base64url')]),format:'der',type:'spki'});
const sid='AAAAAAAAAAAAAAAAAAAAAA', requestSig=b64(Buffer.alloc(64,1)), ts=1800000000;
function signature(text){return b64(sign(null,Buffer.from(text),privateKey));}
function event(s,seq,data,prev,end=false,frameTs=ts){
  const sig=signature(['mcp-jack/stream1/frame',s,String(seq),String(frameTs),prev,hash(Buffer.from(data))].join('\n'));
  return {wire:`event: ${end?'jack-end':'message'}\ndata: ${data}\njack: seq=${seq},ts=${frameTs},sig=${sig}\n\n`,sig};
}
function validStream(){
  const openSig=signature(['mcp-jack/stream1/open','200',requestSig,svc.kid,String(ts),sid].join('\n'));
  const zero=event(sid,0,'{"n":0}',openSig), one=event(sid,1,'{"n":1}',zero.sig), end=event(sid,2,'',one.sig,true);
  const body=Buffer.from(zero.wire+one.wire+end.wire);
  const headers=Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nJack-Auth: s1 kid=${svc.kid},ts=${ts},sid=${sid},sig=${openSig}\r\n`,'latin1');
  return {body,headers,openSig,sid,events:[zero,one,end]};
}
function chunked(fixture){
  const body=fixture.body;
  const cuts=[1,17,body.length>>1,body.length-3].filter((v,i,a)=>v>0&&v<body.length&&a.indexOf(v)===i).sort((a,b)=>a-b);
  const parts=[];let start=0;for(const end of [...cuts,body.length]){parts.push(body.subarray(start,end));start=end;}
  return Buffer.concat([fixture.headers,Buffer.from('Transfer-Encoding: chunked\r\n\r\n'),...parts.flatMap(p=>[Buffer.from(`${p.length.toString(16)};fixture=yes\r\n`),p,Buffer.from('\r\n')]),Buffer.from('0\r\nX-Fixture-Trailer: retained-semantically\r\n\r\n')]);
}
function decodeChunked(data){let at=0;const parts=[];while(true){const e=data.indexOf('\r\n',at);assert.ok(e>=0,'chunk size line');const size=parseInt(data.subarray(at,e).toString('ascii').split(';')[0],16);at=e+2;if(!size){const end=data.indexOf('\r\n\r\n',at);if(end<0){assert.equal(data.subarray(at,at+2).toString(),'\r\n');return Buffer.concat(parts);}return Buffer.concat(parts);}assert.ok(data.length>=at+size+2);parts.push(data.subarray(at,at+size));assert.equal(data.subarray(at+size,at+size+2).toString(),'\r\n');at+=size+2;}}
function parseResponse(raw){const split=raw.indexOf('\r\n\r\n');assert.ok(split>=0,'HTTP response head');const head=raw.subarray(0,split).toString('latin1'),body=raw.subarray(split+4);assert.match(head,/^HTTP\/1\.1 200 OK/);const length=/\r\ncontent-length:\s*(\d+)/i.exec(`\r\n${head}`),te=/\r\ntransfer-encoding:\s*chunked/i.test(`\r\n${head}`);assert.equal(!!length, !te,'one valid rebuilt body framing');const decoded=te?decodeChunked(body):body; if(length)assert.equal(Number(length[1]),decoded.length,'rebuilt Content-Length');return {head,body:decoded,wireBody:body,chunked:te};}
function parseEvents(body){const text=body.toString('latin1');return text.split(/(?<=\n\n)/).filter(Boolean);}
function run(args,extraEnv={},timeoutMs=12000){return new Promise((resolveRun,rejectRun)=>{
  const child=spawn(process.execPath,[join(root,'interop/stream.mjs'),...args],{cwd:root,env:{...process.env,...extraEnv},stdio:['ignore','pipe','pipe'],windowsHide:true});let out='',err='',done=false,escalation;
  const finish=fn=>value=>{if(done)return;done=true;clearTimeout(timer);if(escalation)clearTimeout(escalation);fn(value);};
  const timer=setTimeout(()=>{if(done)return;child.kill('SIGTERM');escalation=setTimeout(()=>{if(!done)child.kill('SIGKILL');},500);},timeoutMs);
  child.stdout.on('data',x=>out+=x);child.stderr.on('data',x=>err+=x);child.once('error',finish(rejectRun));child.once('close',code=>finish(resolveRun)({code,out,err}));
});}
async function relayControl(transform,framing='chunked',scenario={}){
  const sockets=new Set(),fixture=validStream();let served=false;
  const upstreamServer=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});socket.once('data',()=>{if(served)return;served=true;let response;if(framing==='chunked')response=chunked(fixture);else response=Buffer.concat([fixture.headers,Buffer.from(`Content-Length: ${fixture.body.length}\r\n\r\n`),fixture.body]);socket.end(response);});});
  await new Promise((ok,no)=>{upstreamServer.once('error',no);upstreamServer.listen(0,'127.0.0.1',ok);});let relay;
  try{
    relay=await startRelay({upstreamPort:upstreamServer.address().port,transform,scenario:{relay_options:{seq:1},...scenario}});
    const raw=await new Promise((ok,no)=>{const socket=net.connect(relay.port,'127.0.0.1');sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.once('connect',()=>socket.write('GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n'));const chunks=[];socket.on('data',b=>chunks.push(b));socket.once('error',no);socket.once('end',()=>ok(Buffer.concat(chunks)));socket.setTimeout(4000,()=>{socket.destroy();no(Error('relay response timeout'));});});
    const response=parseResponse(raw);assert.match(response.head,/Content-Type: text\/event-stream; charset=utf-8/i);assert.match(response.head,/Cache-Control: no-cache/i);assert.match(response.head,/Jack-Auth:/i);assert.doesNotMatch(response.head,/Trailer:|X-Fixture-Trailer:/i);
    const events=parseEvents(response.body),text=response.body.toString('latin1');
    if(transform==='pass'){assert.equal(events.length,3);assert.equal(relay.applied(),false);}
    else {assert.equal(relay.applied(),true,`${transform} applied`);}
    if(transform==='drop')assert.equal(events.length,2);
    if(transform==='reorder')assert.ok(text.indexOf('seq=1')<text.indexOf('seq=0'));
    if(transform==='edit-data'){assert.equal(response.body.length,fixture.body.length);let diffs=0;for(let i=0;i<fixture.body.length;i++)if(response.body[i]!==fixture.body[i])diffs++;assert.equal(diffs,1,'edit-data changes exactly one wire byte');assert.notEqual(response.body.toString('latin1'),fixture.body.toString('latin1'));}
    if(transform==='truncate')assert.ok(events.every(e=>!/^event: jack-end$/m.test(e)));
    if(transform==='replay')assert.equal((text.match(/seq=0/g)||[]).length,2);
    assert.equal(verify(null,Buffer.from(['mcp-jack/stream1/open','200',requestSig,svc.kid,String(ts),sid].join('\n')),publicKey,Buffer.from(fixture.openSig,'base64url')),true);
    return response;
  }finally{if(relay)await relay.close();for(const socket of sockets)socket.destroy();await new Promise(r=>upstreamServer.close(r));}
}
export async function selfTest(){
  let checks=0,passed=0;const failures=[];
  const report=(name,fn,core=false)=>{if(core)checks++;try{fn();if(core)passed++;console.log(`self-test PASS ${name}`);}catch(error){failures.push(name);console.log(`self-test FAIL ${name}: ${String(error?.message??error).slice(0,8000)}`);}};
  const attempt=async(name,fn)=>{let failure;try{await fn();}catch(error){failure=error;}report(name,()=>{if(failure)throw failure;});};
  const targetPath='interop/tools/fakes/stream/targets.json',target=JSON.parse(readFileSync(join(root,targetPath),'utf8'));
  report('fake target configuration',()=>assert.deepEqual(Object.keys(target),['fake']));
  const docs=JSON.parse(readFileSync(join(root,'interop/stream-scenarios.json'),'utf8'));
  report('active matrix has exactly nine cases',()=>assert.equal(docs.matrices.stream.length,9,'active stream matrix has nine scenarios'));
  for(const scenario of docs.matrices.stream){
    const result=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario',scenario.id]);
    report(`stream/${scenario.id}`,()=>{assert.equal(result.code,0,`stream/${scenario.id}: ${result.out}${result.err}`);assert.match(result.out,new RegExp(`PASS ${scenario.id}`));},true);
  }
  for(const scenario of docs.matrices.staged){
    const result=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario',scenario.id,'--staged-only']);
    report(`staged/${scenario.id}`,()=>{assert.equal(result.code,0,`staged/${scenario.id}: ${result.out}${result.err}`);assert.match(result.out,new RegExp(`PASS ${scenario.id}`));},true);
  }
  for(const matrix of ['rotation-stream','durable-stream']){const deferred=await run(['--matrix',matrix,'--list']);report(`${matrix} deferred CLI`,()=>{assert.equal(deferred.code,2,`${matrix} --list must be deferred`);assert.match(deferred.out,new RegExp(`DEFERRED matrix=${matrix}`));});}
  for(const name of ['pass','drop','edit-data','truncate'])await attempt(`relay ${name} chunked`,()=>relayControl(name,'chunked'));
  await attempt('relay pass content-length',()=>relayControl('pass','length'));
  const noTamper=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario','relay-edit-data'],{JACK_STREAM_SELFTEST_NO_TAMPER:'1'});report('no-tamper negative control',()=>{assert.notEqual(noTamper.code,0);assert.match(noTamper.out,/FAIL relay-edit-data/);});
  for(const scenario of docs.matrices.staged.filter(item=>item.relay)){
    const noTamper=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario',scenario.id,'--staged-only'],{JACK_STREAM_SELFTEST_NO_TAMPER:'1'});
    report(`no-tamper ${scenario.id} negative control`,()=>{assert.notEqual(noTamper.code,0);assert.match(noTamper.out,new RegExp(`FAIL ${scenario.id}`));});
  }
  const ignoredLimit=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario','concurrency-limit','--staged-only'],{JACK_STREAM_FAKE_IGNORE_LIMIT:'1'});report('ignored concurrency limit negative control',()=>{assert.notEqual(ignoredLimit.code,0);assert.match(ignoredLimit.out,/FAIL concurrency-limit/);});
  const baseline=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario','progress-final']);report('fake-client positive baseline',()=>{assert.equal(baseline.code,0,`fake-client positive baseline: ${baseline.out}${baseline.err}`);assert.match(baseline.out,/PASS progress-final/);});
  const badEvidence=await run(['--matrix','stream','--targets',targetPath,'--servers','fake','--clients','fake','--scenario','progress-final'],{JACK_STREAM_FAKE_BAD_EVIDENCE:'1'});report('fake-client evidence deviation rejected',()=>{assert.equal(badEvidence.code,1,`fake-client invalid evidence control exit: ${badEvidence.out}${badEvidence.err}`);assert.match(badEvidence.out,/FAIL progress-final/);});
  const listed=await run(['--list']);report('--list exact active scenarios',()=>{assert.equal(listed.code,0);assert.deepEqual(listed.out.trim().split(/\r?\n/),docs.matrices.stream.map(s=>s.id));});
  const stagedList=await run(['--list','--include-staged']);report('--include-staged list',()=>{assert.equal(stagedList.code,0);assert.deepEqual(stagedList.out.trim().split(/\r?\n/),[...docs.matrices.stream,...docs.matrices.staged].map(s=>s.id));});
  const stagedOnlyList=await run(['--list','--staged-only']);report('--staged-only list',()=>{assert.equal(stagedOnlyList.code,0);assert.deepEqual(stagedOnlyList.out.trim().split(/\r?\n/),docs.matrices.staged.map(s=>s.id));});
  const invalid=await run(['--invalid-option']);report('invalid CLI option rejected',()=>assert.equal(invalid.code,2,'invalid CLI option'));
  const tmp=mkdtempSync(join(tmpdir(),'jack-stream-selftest-'));try{const badTargets=join(tmp,'bad-targets.json');writeFileSync(badTargets,JSON.stringify({fake:{server:['node','x'],client:['node','y']}}));const invalidRole=await run(['--targets',badTargets,'--servers','fake','--clients','fake']);report('invalid target roles rejected',()=>assert.equal(invalidRole.code,2,'invalid target roles'));}finally{rmSync(tmp,{recursive:true,force:true});}
  console.log(`INTEROP-SUMMARY matrix=stream pairs=1 checks=${checks} passed=${passed} failed=${checks-passed} result=${failures.length?'fail':'pass'}`);
  if(failures.length)throw Error(`self-test failures: ${failures.join(', ')}`);
}
if(import.meta.url===`file://${process.argv[1]}`){selfTest().catch(error=>{console.error(error);process.exitCode=1;});}
