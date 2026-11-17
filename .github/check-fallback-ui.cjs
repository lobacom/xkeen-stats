const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
(async()=>{
const nodes=new Map(),handlers=new Map(),events=new Map(),calls=[];
function node(id){if(!nodes.has(id)){let html='';nodes.set(id,{value:'',checked:false,textContent:'',classList:{contains:()=>true,toggle(){},add(){},remove(){}},addEventListener:(name,fn)=>handlers.set(id+':'+name,fn),removeAttribute(){},replaceChildren(){html=''},get innerHTML(){return html},set innerHTML(value){html=value}})}return nodes.get(id)}
let snapshot={enabled:true,lan_enabled:true,lan_exit:'de',revision:'x1',fallback:{enabled:false,outbound:'',after_minutes:10,revision:'f1',runtime:{}},outbounds:[{tag:'de',title:'DE'},{tag:'sg',title:'SG'},{tag:'direct',title:'Direct',direct:true}],inbounds:[],clients:[]},fail=false;
const document={getElementById:node,querySelectorAll:()=>[],addEventListener:(name,fn)=>events.set(name,fn),dispatchEvent:e=>events.get(e.type)?.(e)};
const context={document,window:{},Event:class{constructor(type){this.type=type}},fetch:async(path,options)=>{
 calls.push({path,options});if(options?.method==='POST'){
  if(fail)return {ok:false,status:409,json:async()=>({error:'stale settings'})};
  const body=JSON.parse(options.body);
  if(path.endsWith('/fallback'))snapshot={...snapshot,fallback:{...body,revision:'f2',runtime:{}}};
  if(path.endsWith('/fallback/switch'))snapshot={...snapshot,lan_exit:snapshot.fallback.outbound};
 }
 return {ok:true,status:200,json:async()=>structuredClone(snapshot)};
}};
vm.runInNewContext(fs.readFileSync('management.js','utf8'),context);
document.dispatchEvent({type:'vpn-auth-ready'});await new Promise(setImmediate);
assert.equal(node('vpn-fallback-minutes').value,10);assert.equal(node('vpn-fallback-switch').disabled,true);
node('vpn-fallback-outbound').value='sg';node('vpn-fallback-minutes').value='7';node('vpn-fallback-enabled').checked=true;
handlers.get('vpn-fallback-minutes:input')();
const health={health:{enabled:true,mode:'tcp'},status:()=>({state:'up',text:'up'}),formatTime:()=> '12:00'};
document.dispatchEvent({type:'vpn-exit-health',detail:health});
assert.equal(node('vpn-fallback-minutes').value,'7','refresh lost unsaved delay');assert.equal(node('vpn-fallback-switch').disabled,true);
await handlers.get('vpn-fallback-form:submit')({preventDefault(){}});
assert.equal(calls.at(-1).path,'/api/manage/fallback');assert.equal(JSON.parse(calls.at(-1).options.body).after_minutes,7);assert.equal(snapshot.lan_exit,'de','saving reserve changed LAN');assert.equal(node('vpn-fallback-switch').disabled,false);
await node('vpn-fallback-switch').onclick();assert.equal(calls.at(-1).path,'/api/manage/fallback/switch');assert.equal(snapshot.lan_exit,'sg');assert.equal(node('vpn-fallback-switch').disabled,true);
node('vpn-fallback-minutes').value='0';handlers.get('vpn-fallback-minutes:input')();const beforeInvalid=calls.length;
await handlers.get('vpn-fallback-form:submit')({preventDefault(){}});assert.equal(calls.length,beforeInvalid,'invalid delay submitted');
node('vpn-fallback-minutes').value='12';fail=true;await handlers.get('vpn-fallback-form:submit')({preventDefault(){}});assert.equal(node('vpn-fallback-minutes').value,'12','failed save lost draft');fail=false;
snapshot={...snapshot,lan_exit:'de'};
document.dispatchEvent({type:'vpn-exit-health',detail:{...health,fallbackRuntime:{current:'de',last_switch:100,switched_to:'de'}}});
await new Promise(setImmediate);assert.match(node('vpn-current').textContent,/DE/,'automatic switch left stale active card');assert.equal(node('vpn-fallback-minutes').value,'12','automatic update lost draft');
document.dispatchEvent({type:'vpn-auth-lost'});assert.equal(node('vpn-fallback-enabled').checked,false);
console.log('Reserve UI: settings, delay, manual/automatic switch, validation, failed saves and draft preservation passed');
})().catch(error=>{console.error(error);process.exitCode=1});
