const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
(async()=>{
const nodes=new Map(),handlers=new Map(),events=new Map(),calls=[];
function node(id){
 if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],textContent:'',innerHTML:'',open:false,classList:{contains:()=>true,toggle(){},add(){},remove(){}},
  addEventListener:(type,fn)=>handlers.set(id+':'+type,fn),focus(){},showModal(){this.open=true},close(){this.open=false},removeAttribute(){},
  replaceChildren(...children){this.children=children;this.value=children.find(c=>!c.disabled)?.value||''},
  querySelectorAll(){return [...this.innerHTML.matchAll(/<input[^>]*value="([^"]*)"([^>]*)>/g)].filter(m=>m[2].includes('checked')&&!m[2].includes('disabled')).map(m=>({value:m[1]}))}});
 return nodes.get(id);
}
const document={getElementById:node,querySelectorAll:()=>[],addEventListener:(name,fn)=>events.set(name,fn),dispatchEvent:e=>events.get(e.type)?.(e)};
let snapshot={enabled:true,lan_enabled:true,lan_exit:'exit-a',revision:'r1',settings_revision:'s1',
 outbounds:['a','b','a-v4','b-v4'].map(tag=>({tag:'exit-'+tag,title:'Output '+tag})),
 client_exits:['a','b','a-v4','b-v4'].map(tag=>({tag:'exit-'+tag,title:'Output '+tag,inbounds:tag.includes('v4')?[]:['input-'+tag]})),
 inbounds:['a','b'].map(tag=>({tag:'input-'+tag,title:'Transport '+tag,export_ready:true})),clients:[{name:'alice',inbounds:['input-a','input-b']}]};
const context={document,window:{},Event:class{constructor(type){this.type=type}},Option:class{constructor(text,value){this.text=text;this.value=value;this.disabled=false}},fetch:async(path,options)=>{
 calls.push({path,body:options?.body&&JSON.parse(options.body)});
 if(path.endsWith('/profile'))return {ok:true,status:200,json:async()=>({name:'alice',uri:'vless://example@vpn.example.test:443',qr:'data:image/png;base64,AA==',settings_revision:'s1'})};
 return {ok:true,status:200,json:async()=>structuredClone(snapshot)};
}};
vm.runInNewContext(fs.readFileSync('management.js','utf8'),context);
document.dispatchEvent({type:'vpn-auth-ready'});await new Promise(setImmediate);
const edit=()=>handlers.get('rows:click')({target:{closest:()=>({dataset:{vpnEdit:'alice'}})}});
edit();assert.equal((node('vpn-client-inputs').innerHTML.match(/type="checkbox"/g)||[]).length,4);assert.equal((node('vpn-client-inputs').innerHTML.match(/disabled/g)||[]).length,2);
assert.match(node('vpn-client-inputs').innerHTML,/Output a-v4/);assert.match(node('vpn-client-inputs').innerHTML,/ещё не настроен/);
await node('vpn-client-profile').onclick();assert.equal(node('vpn-profile-input').children.length,4);assert.equal(node('vpn-profile-input').children.filter(o=>o.disabled).length,2);
assert.equal(calls.at(-1).body.inbound,'input-a','missing endpoint exported as valid profile');
for(const tag of ['a-v4','b-v4']){
 snapshot.inbounds.push({tag:'input-'+tag,title:'Transport '+tag,export_ready:true});
 snapshot.client_exits.find(e=>e.tag==='exit-'+tag).inbounds=['input-'+tag];snapshot.clients[0].inbounds.push('input-'+tag);
}
await node('vpn-refresh').onclick();edit();assert.equal((node('vpn-client-inputs').innerHTML.match(/type="checkbox"/g)||[]).length,4);assert.equal((node('vpn-client-inputs').innerHTML.match(/disabled/g)||[]).length,0);
await node('vpn-client-profile').onclick();assert.equal(node('vpn-profile-input').children.length,4);assert.equal(node('vpn-profile-input').children.filter(o=>o.disabled).length,0);
for(const option of node('vpn-profile-input').children){node('vpn-profile-input').value=option.value;await node('vpn-profile-input').onchange();assert.equal(calls.at(-1).body.inbound,option.value)}
edit();await handlers.get('vpn-client-form:submit')({preventDefault(){}});
assert.deepEqual(calls.findLast(c=>c.path==='/api/manage/client').body.inbounds,['input-a','input-b','input-a-v4','input-b-v4'],'editor sent exit tags instead of real profile inbounds');
// Личные права доступа сохраняются: выход виден, но чужой профиль не экспортируется.
snapshot.clients[0].inbounds=['input-a'];await node('vpn-refresh').onclick();edit();await node('vpn-client-profile').onclick();
assert.equal(node('vpn-profile-input').children.filter(o=>o.disabled).length,3);assert.match(node('vpn-profile-input').children[2].text,/не добавлен клиенту/);
snapshot.clients[0].inbounds=[];await node('vpn-refresh').onclick();edit();const before=calls.length;await node('vpn-client-profile').onclick();
assert.equal(calls.length,before,'empty profile selection sent a fake export request');assert.equal(node('vpn-prefix-save').disabled,true);assert.equal(node('vpn-profile-uri').value,'');
console.log('Client exits UI: all four outputs, missing-input state, four real profiles, preserved client permissions and no fake exports passed');
})().catch(error=>{console.error(error);process.exitCode=1});
