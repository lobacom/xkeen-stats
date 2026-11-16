const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
(async()=>{
const nodes=new Map(),handlers=new Map(),events=new Map(),calls=[];
function node(id){if(!nodes.has(id)){let html='';nodes.set(id,{textContent:'',writes:0,classList:{contains:()=>true,toggle(){},add(){},remove(){}},addEventListener:(name,fn)=>handlers.set(id+':'+name,fn),removeAttribute(){},replaceChildren(){html=''},get innerHTML(){return html},set innerHTML(value){html=value;this.writes++}})}return nodes.get(id)}
let snapshot={enabled:true,lan_enabled:true,lan_exit:'de',revision:'revision',outbounds:[{tag:'de',title:'Интернет через Германию'},{tag:'sg',title:'Интернет через Сингапур'},{tag:'direct',title:'Без VPN — напрямую',direct:true}],inbounds:[],clients:[]};
let fail=false;
const document={getElementById:node,querySelectorAll:()=>[],addEventListener:(name,fn)=>events.set(name,fn),dispatchEvent:e=>events.get(e.type)?.(e)};
const context={document,window:{},Event:class{constructor(type){this.type=type}},fetch:async(path,options)=>{calls.push({path,options});if(path.endsWith('/lan')){if(fail)return {ok:false,status:409,json:async()=>({error:'Конфигурация изменена'})};snapshot={...snapshot,lan_exit:JSON.parse(options.body).outbound}}return {ok:true,status:200,json:async()=>snapshot}}};
vm.runInNewContext(fs.readFileSync('management.js','utf8'),context);
document.dispatchEvent({type:'vpn-auth-ready'});await new Promise(setImmediate);
assert.match(node('exit-health-items').innerHTML,/Отключить VPN/);
assert.match(node('vpn-current').textContent,/Германию/);
const health={health:{enabled:true,mode:'tcp'},status:()=>({state:'up',text:'Сервер доступен',last:100,s:{delay_ms:44}}),formatTime:()=> '12:00'};
document.dispatchEvent({type:'vpn-exit-health',detail:health});
assert.match(node('exit-health-items').innerHTML,/Сервер доступен · 44 мс/);
assert.match(node('exit-health-items').innerHTML,/Сейчас используется/);
let writes=node('exit-health-items').writes;document.dispatchEvent({type:'vpn-exit-health',detail:health});assert.equal(node('exit-health-items').writes,writes,'unchanged refresh replaced focused controls');
assert.equal(calls.length,1,'rendering changed the VPN');
const click=tag=>handlers.get('exit-health-items:click')({target:{closest:()=>({dataset:{vpnExit:tag}})}});
await click('direct');assert.equal(calls.at(-1).path,'/api/manage/lan');assert.equal(JSON.parse(calls.at(-1).options.body).outbound,'direct');
assert.match(node('vpn-current').textContent,/без VPN/);assert.match(node('exit-health-items').innerHTML,/VPN отключён/);
fail=true;await click('sg');assert.match(node('vpn-current').textContent,/без VPN/,'failed change altered active card');assert.match(node('vpn-message').textContent,/Конфигурация изменена/);
fail=false;await click('sg');assert.match(node('vpn-current').textContent,/Сингапур/);
document.dispatchEvent({type:'vpn-auth-lost'});assert.equal(context.window.vpnManagement.enabled,false);assert.equal(node('exit-health-items').innerHTML,'');
console.log('Unified LAN cards: status, current selection, off/on, failed apply and focus preservation passed');
})().catch(error=>{console.error(error);process.exitCode=1});
