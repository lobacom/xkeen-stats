const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync('index.html','utf8');
const source=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]).find(s=>s.includes("document.getElementById('table-scroll-top')"));
assert.ok(source,'scroll controller missing');
function environment(withObserver){
 const elements=new Map(),windowEvents={},documentEvents={},frames=[],observers=[];
 function element(id){if(!elements.has(id)){const classes=new Set();elements.set(id,{style:{},scrollLeft:0,scrollWidth:1200,clientWidth:800,events:{},classList:{toggle:(name,on)=>on?classes.add(name):classes.delete(name),contains:name=>classes.has(name)},addEventListener(type,fn){this.events[type]=fn}})}return elements.get(id)}
 const top=element('table-scroll-top'),viewport=element('stats-table-wrap');top.clientWidth=802;
 const context={document:{getElementById:element,addEventListener:(type,fn)=>documentEvents[type]=fn},window:{addEventListener:(type,fn)=>windowEvents[type]=fn},requestAnimationFrame:fn=>{frames.push(fn);return frames.length},ResizeObserver:withObserver?class{constructor(fn){this.fn=fn;this.targets=[];observers.push(this)}observe(target){this.targets.push(target)}}:undefined};
 vm.runInNewContext(source,context);
 return {element,top,viewport,windowEvents,documentEvents,frames,observers,flush(){while(frames.length)frames.shift()()}};
}
const e=environment(true);e.flush();
assert.equal(e.element('table-scroll-tools').classList.contains('hidden'),false);
assert.equal(e.element('table-scroll-spacer').style.width,'1202px','upper bar must have the same scroll range, including border width');
e.top.scrollLeft=175;e.top.events.scroll();assert.equal(e.viewport.scrollLeft,175,'top scrollbar did not move table');
e.viewport.scrollLeft=400;e.viewport.events.scroll();assert.equal(e.top.scrollLeft,400,'table did not move top scrollbar');
assert.equal(e.observers[0].targets.length,2,'table and viewport resizes must both be observed');
e.viewport.scrollWidth=800;e.observers[0].fn();e.windowEvents.resize();assert.equal(e.frames.length,1,'resize work was not batched');e.flush();
assert.equal(e.element('table-scroll-tools').classList.contains('hidden'),true,'bar shown without overflow');
e.viewport.clientWidth=360;e.top.clientWidth=362;e.observers[0].fn();e.flush();assert.equal(e.element('table-scroll-tools').classList.contains('hidden'),false,'bar did not return on narrow screen');
e.viewport.clientWidth=0;e.observers[0].fn();e.flush();assert.equal(e.element('table-scroll-tools').classList.contains('hidden'),true,'hidden dashboard left visible controls');
const fallback=environment(false);fallback.flush();fallback.viewport.scrollWidth=700;fallback.documentEvents['vpn-auth-ready']();fallback.flush();assert.equal(fallback.element('table-scroll-tools').classList.contains('hidden'),true);
console.log('Table UI: bidirectional scrolling, equal scroll ranges, resize batching, overflow-only controls and hidden-dashboard recovery passed');
