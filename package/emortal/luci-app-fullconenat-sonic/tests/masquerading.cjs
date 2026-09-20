// Exercise the actual LuCI UCI staging layer; no router or RPC is contacted.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const root = path.resolve(process.argv[2] || '.');
const uciSource = fs.readFileSync(`${root}/feeds/luci/modules/luci-base/htdocs/luci-static/resources/uci.js`, 'utf8');
const helperSource = fs.readFileSync(process.argv[3] || `${root}/package/emortal/luci-app-fullconenat-sonic/htdocs/luci-static/resources/tools/fullconenat-sonic.js`, 'utf8');
const value = v => v == null ? undefined : v;
function fixture(fullcone, masq, masq6, global) {
 const uci = new Function('rpc','baseclass',uciSource)({ declare: () => () => { throw Error('Unexpected RPC'); } },{extend:x=>x});
 uci.__init__(); uci.createSID=()=> 'newzone';
 const zone={'.name':'zone','.type':'zone','.index':1,name:'wan'};
 for(const [k,v] of Object.entries({fullcone,masq,masq6}))if(v!==undefined)zone[k]=v;
 uci.state.values={firewall:{defaults:{'.name':'defaults','.type':'defaults','.index':0,fullcone:global},zone,
  other:{'.name':'other','.type':'zone','.index':2,name:'lan',fullcone:'0',masq:'0',masq6:'1'}}};
 const helper=new Function('baseclass','form','uci','_',helperSource)({extend:x=>x},{Flag:{}},uci,x=>x);
 return {uci,helper};
}
async function save(helper,uci,modal,mutate,callback) {
 const map={async save(cb,silent){assert.equal(silent,true);await mutate();return await cb();}};
 if(modal) {
  const section={taboption(){return {};}};
  helper.addZone(section);section.addModalOptions({map});
 } else helper.attach(map);
 await map.save(callback,true);
}
(async()=>{
 let count=0;
 const values=[undefined,'0','1'];
 for(const modal of [false,true])for(const fc of values)for(const m4 of values)for(const m6 of values)for(const global of ['0','1']) {
  const actions=[
   ['fullcone','1', '1', fc==='1'?m4:'1',m6],
   ['fullcone','0', '0',m4,m6],
   ['masq','1', fc,'1',m6],
   ['masq',undefined,m4==='1'?'0':fc,undefined,m6],
   ['masq6','1',fc,m4,'1'],
   ['masq6',undefined,fc,m4,undefined],
   ['noop',undefined,fc,m4,m6]
  ];
  for(const [key,next,wantFc,wantM4,wantM6] of actions) {
   const {uci,helper}=fixture(fc,m4,m6,global);
   const other=structuredClone(uci.get('firewall','other'));
   let called=false;
   await save(helper,uci,modal,()=>{
    if(key==='noop')return;
    if(next===undefined)uci.unset('firewall','zone',key);else uci.set('firewall','zone',key,next);
   },()=>{called=true;assert.equal(value(uci.get('firewall','zone','fullcone')),wantFc);});
   assert(called);
   for(const [key,want] of Object.entries({fullcone:wantFc,masq:wantM4,masq6:wantM6}))assert.equal(value(uci.get('firewall','zone',key)),want,`${modal}/${key}`);
   assert.deepEqual(uci.get('firewall','other'),other);
   const after=structuredClone(uci.get('firewall','zone'));
   await save(helper,uci,modal,()=>{},()=>{});
   assert.deepEqual(uci.get('firewall','zone'),after);
   count++;
  }
 }
 for(const modal of [false,true]) {
  const {uci,helper}=fixture('0','1','1','1');
  await save(helper,uci,modal,()=>{uci.set('firewall','zone','fullcone','1');uci.unset('firewall','zone','masq');},()=>{});
  assert.equal(uci.get('firewall','zone','fullcone'),'0');assert.equal(value(uci.get('firewall','zone','masq')),undefined);assert.equal(uci.get('firewall','zone','masq6'),'1');count++;
  await save(helper,uci,modal,()=>{const id=uci.add('firewall','zone');uci.set('firewall',id,'name','new');uci.set('firewall',id,'fullcone','1');uci.set('firewall',id,'masq6','0');},()=>{});
  assert.equal(uci.get('firewall','newzone','masq'),'1');assert.equal(uci.get('firewall','newzone','masq6'),'0');count++;
  const before=structuredClone(uci.get('firewall','zone'));
  await save(helper,uci,modal,()=>uci.set('firewall','defaults','fullcone','0'),()=>{});
  assert.deepEqual(uci.get('firewall','zone'),before);count++;
 }
 console.log(`PASS ${count} staged LuCI cases: table/modal, IPv4 transitions, IPv6 independence, no-op saves and new zones`);
})().catch(e=>{console.error(e);process.exitCode=1;});
