const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
(async()=>{
const nodes=new Map(),events=new Map(),calls=[];
class Element {
 constructor(id=''){this.id=id;this.children=[];this.listeners={};this.value='';this.checked=false;this.open=false;this.disabled=false;this.textContent='';this.classList={contains:()=>false,toggle(){}};}
 append(...items){this.children.push(...items)} replaceChildren(...items){this.children=items}
 querySelectorAll(){return this.children.flatMap(e=>[e,...e.querySelectorAll()])}
 addEventListener(type,fn){this.listeners[type]=fn} showModal(){this.open=true} close(){this.open=false}
}
function node(id){if(!nodes.has(id))nodes.set(id,new Element(id));return nodes.get(id)}
let state={available:true,configured:true,active:true,applied:1000,revision:'r1',templates:JSON.parse(fs.readFileSync('bypass_templates.json','utf8')),rules:[{id:'steam',name:'Steam <script>',enabled:true,network:'udp',ports:'27015-27140',scope:'devices',destinations:['192.0.2.1/32'],devices:[{mac:'02:00:00:00:00:01',name:'Gaming'}]}]},fail=false;
const document={getElementById:node,createElement:()=>new Element(),addEventListener:(name,fn)=>events.set(name,fn)};
const context={document,Date,Math,fetch:async(path,options)=>{
 calls.push({path,options});
 if(path.endsWith('/devices'))return {ok:true,status:200,json:async()=>({devices:[{mac:'02:00:00:00:00:01',name:'Gaming',ip:'192.168.1.77',online:true},{mac:'02:00:00:00:00:02',name:'Offline',online:false}]})};
 if(options?.method==='POST'){
  if(fail)return {ok:false,status:409,json:async()=>({error:'stale revision'})};
  const input=JSON.parse(options.body);assert.equal(input.revision,state.revision);state={...state,rules:input.rules,revision:state.revision+'x'};
 }
 return {ok:true,status:200,json:async()=>structuredClone(state)};
}};
vm.runInNewContext(fs.readFileSync('bypass.js','utf8'),context);
const settle=()=>new Promise(setImmediate),click=async e=>{await e.listeners.click();await settle()};
assert.equal(calls.length,0,'collapsed section must not poll');
node('bypass-panel').open=true;node('bypass-panel').listeners.toggle();await settle();
assert.equal(calls.length,1);assert.equal(node('bypass-rules').children.length,1);
const actions=()=>node('bypass-rules').children[0].children.at(-1).children;
assert.equal(node('bypass-rules').children[0].children[0].children[0].textContent,'Steam <script>','names must remain text');
await click(actions()[0]);assert.equal(state.rules[0].enabled,false);
await click(actions()[1]);assert.equal(node('bypass-edit').open,true);assert.equal(node('bypass-scope').value,'devices');
assert.equal(node('bypass-devices').children.length,2,'saved and offline adapters must stay distinct');
assert.equal(node('bypass-template').children.length,5,'four templates plus manual selection');
const posts=()=>calls.filter(c=>c.options?.method==='POST').length;
const beforeEditTemplate=posts();node('bypass-template').value='kinopoisk';node('bypass-template').listeners.change();
assert.equal(node('bypass-scope').value,'devices','template broadened edited rule to all LAN');assert.equal(node('bypass-enabled').checked,false,'template enabled disabled rule');assert.equal(posts(),beforeEditTemplate,'template choice applied before save');
assert.equal(node('bypass-devices').children[0].children[0].checked,true,'template lost chosen MAC');
node('bypass-name').value='Updated';fail=true;
await node('bypass-form').listeners.submit({preventDefault(){}});
assert.equal(node('bypass-edit').open,true);assert.equal(node('bypass-name').value,'Updated');assert.equal(node('bypass-edit-error').textContent,'stale revision');
fail=false;await node('bypass-form').listeners.submit({preventDefault(){}});assert.equal(node('bypass-edit').open,false);assert.equal(state.rules[0].name,'Updated');assert.equal(state.rules[0].devices[0].mac,'02:00:00:00:00:01');
await click(node('bypass-add'));assert.equal(node('bypass-template').value,'','previous template leaked to new editor');
const beforeTemplates=posts();
for(const template of state.templates){
 node('bypass-template').value=template.id;node('bypass-template').listeners.change();
 assert.equal(node('bypass-name').value,template.name);assert.equal(node('bypass-network').value,template.network);assert.equal(node('bypass-ports').value,template.ports);
 assert.equal(node('bypass-addresses').value,template.destinations.join('\n'));assert.equal(node('bypass-scope').value,template.scope);assert.match(node('bypass-template-info').textContent,/17.11.2026/);
}
assert.equal(posts(),beforeTemplates,'choosing templates sent mutation requests');
assert.equal(node('bypass-scope').value,'devices','Steam must request users own adapters');
node('bypass-template').value='';node('bypass-template').listeners.change();assert.notEqual(node('bypass-addresses').value,'','manual mode discarded draft');
node('bypass-scope').value='devices';node('bypass-name').value='New';node('bypass-addresses').value='198.51.100.1';
const before=calls.length;await node('bypass-form').listeners.submit({preventDefault(){}});assert.equal(calls.length,before,'empty selected scope must not become all LAN');
node('bypass-device-mac').value='02:00:00:00:00:03';node('bypass-device-name').value='Manual';await click(node('bypass-device-add'));
await node('bypass-form').listeners.submit({preventDefault(){}});assert.equal(state.rules.length,2);assert.equal(state.rules[1].devices[0].mac,'02:00:00:00:00:03');
await click(actions()[2]);assert.equal(node('bypass-delete').open,true);await click(node('bypass-delete-cancel'));assert.equal(state.rules.length,2);
await click(actions()[2]);await click(node('bypass-delete-confirm'));assert.equal(state.rules.length,1);
events.get('vpn-auth-lost')();assert.equal(node('bypass-rules').children.length,0);assert.equal(node('bypass-add').disabled,true);
console.log('Bypass UI: four editable templates, no apply before save, scope/MAC preservation, CRUD, failed-save drafts and logout passed');
})().catch(error=>{console.error(error);process.exitCode=1});
