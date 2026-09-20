#!/usr/bin/env python3
"""Run source-extracted NAT models: run-core.py KERNEL_SOURCE OUTPUT_DIR."""
from pathlib import Path
import hashlib,json,re,subprocess,sys
kernel=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
source=(kernel/'net/netfilter/nf_nat_core.c').read_text()
names=['nf_nat_is_fullcone','same_source_endpoint','same_nat_zone','same_reply_dst','__nf_nat_used_3_tuple','nf_nat_used_3_tuple','same_src','find_appropriate_src','find_appropriate_dst','nf_nat_l4proto_unique_tuple','get_unique_tuple','__nf_nat_setup_info','nf_nat_fullcone_supported','nf_nat_setup_info','nf_nat_cleanup_conntrack']
def extract(name):
 m=re.search(r'(?m)^(?:static[^\n]*\n)?(?:static[^\n]* )?'+re.escape(name)+r'\(',source)
 if not m:m=re.search(r'(?m)^static [^\n]*\b'+re.escape(name)+r'\(',source)
 assert m,name
 start=m.start()
 if name=='nf_nat_setup_info':start=source.rfind('unsigned int\n',0,start+1)
 end=source.index('\n}',source.index('{',start))+2
 return source[start:end]
functions={n:extract(n) for n in names}
template=Path(__file__).with_name('core-model.c.in').read_text()
code=template.replace('/* @KERNEL_FUNCTIONS@ */','\n\n'.join(functions.values()))
(out/'core.c').write_text(code)
(out/'provenance.json').write_text(json.dumps({n:hashlib.sha256(s.encode()).hexdigest() for n,s in functions.items()},indent=2)+'\n')
subprocess.run(['gcc','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer','-pthread',str(out/'core.c'),'-o',str(out/'core')],check=True)
with (out/'core.log').open('w') as log:subprocess.run([str(out/'core')],stdout=log,stderr=log,check=True,timeout=120)
print('PASS: core boundary, mixed NAT, 300 lifetime interleavings and 30 concurrency batches (ASan/UBSan host model)')

# Compile the disabled model without the extra conntrack fields or globals.
# The executable also counts real reservation-list visits at increasing sizes.
head,tail=template.split('/* @KERNEL_FUNCTIONS@ */')
head=head.replace('struct hlist_node nat_bysource, nat_by_manip_src;\n bool nat_fullcone;', 'struct hlist_node nat_bysource;\n#if CONFIG_NF_NAT_FULLCONE\n struct hlist_node nat_by_manip_src;\n bool nat_fullcone;\n#endif\n')
head=head.replace('static spinlock_t nf_nat_locks[CONNTRACK_LOCKS],nf_nat_fullcone_locks[CONNTRACK_LOCKS],nf_nat_manip_src_locks[CONNTRACK_LOCKS];', 'static spinlock_t nf_nat_locks[CONNTRACK_LOCKS];\n#if CONFIG_NF_NAT_FULLCONE\nstatic spinlock_t nf_nat_fullcone_locks[CONNTRACK_LOCKS],nf_nat_manip_src_locks[CONNTRACK_LOCKS];\n#endif')
head=head.replace('static struct hlist_head nf_nat_bysource[256],nf_nat_by_manip_src[256];','static struct hlist_head nf_nat_bysource[256];\n#if CONFIG_NF_NAT_FULLCONE\nstatic struct hlist_head nf_nat_by_manip_src[256];\n#endif')
head+='\nstatic unsigned long long visits;\nstatic void pause_for_recycle(const struct nf_conn *ct) {}\n'
optional={'same_source_endpoint','same_nat_zone','same_reply_dst','__nf_nat_used_3_tuple','find_appropriate_dst'}
parts=[]
for name,body in functions.items():
 if name=='__nf_nat_used_3_tuple':body=body.replace('nat_by_manip_src) {','nat_by_manip_src) {\n\t\tvisits++;',1)
 parts.append('#if CONFIG_NF_NAT_FULLCONE\n'+body+'\n#endif' if name in optional else body)
helpers=tail[:tail.index('static void basics(void)')]
cost=r'''
static void cost(unsigned n, bool fullcone) {
 struct nf_conn *cts=calloc(n+1,sizeof(*cts));assert(cts);
 struct nf_nat_range2 r=range(40000,40000,fullcone);
 for(unsigned i=0;i<=n;i++) {
  cts[i]=init_ct(10,5000,10000+i,fullcone);
  if(i==n)visits=0;
  assert(nf_nat_setup_info(&cts[i],&r,NF_NAT_MANIP_SRC)==NF_ACCEPT);
  cts[i].status|=IPS_CONFIRMED;
 }
 assert(visits==(CONFIG_NF_NAT_FULLCONE?2:0));
 printf("{\"enabled\":%d,\"fullcone\":%d,\"flows\":%u,\"visits\":%llu}\n",CONFIG_NF_NAT_FULLCONE,fullcone,n,visits);
 for(unsigned i=0;i<=n;i++)clean(&cts[i]);free(cts);
}
int main(void) {
 for(int i=0;i<CONNTRACK_LOCKS;i++) {
  pthread_mutex_init(&nf_nat_locks[i],NULL);
#if CONFIG_NF_NAT_FULLCONE
  pthread_mutex_init(&nf_nat_fullcone_locks[i],NULL);
  pthread_mutex_init(&nf_nat_manip_src_locks[i],NULL);
#endif
 }
 unsigned ns[]={1,16,256,1024,4096};
 for(unsigned i=0;i<5;i++){cost(ns[i],false);if(CONFIG_NF_NAT_FULLCONE)cost(ns[i],true);}
 return 0;
}
'''
(out/'cost.c').write_text(head+'\n\n'.join(parts)+helpers+cost)
rows=[]
for name,flags in [('enabled',[]),('disabled',['-DAUDIT_SONIC_DISABLED'])]:
 binary=out/('cost-'+name)
 subprocess.run(['gcc','-O2','-pthread',*flags,str(out/'cost.c'),'-o',str(binary)],check=True)
 r=subprocess.run([str(binary)],capture_output=True,text=True,check=True,timeout=120)
 rows.extend(json.loads(line) for line in r.stdout.splitlines())
(out/'cost.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 15 scale/config cases; disabled model has no extra fields, table, locks or reservation visits')
