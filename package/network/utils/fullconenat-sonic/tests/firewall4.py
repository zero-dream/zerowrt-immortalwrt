#!/usr/bin/env python3
"""Usage: firewall4.py REPOSITORY PREPARED_FIREWALL4 OUTPUT_DIR."""
from pathlib import Path
import json,subprocess,re,sys
root=Path(sys.argv[1]).resolve(); src=Path(sys.argv[2]).resolve(); T=Path(sys.argv[3]).resolve(); T.mkdir(parents=True,exist_ok=True)
fixtures=T/'fixtures'; (fixtures/'uci').mkdir(parents=True,exist_ok=True)
(fixtures/'uci/helpers.json').write_text('{}')
def render(label,defaults=None,zone=None,unavailable=False,extra=None):
 d={'input':'REJECT','output':'ACCEPT','forward':'REJECT','fullcone':'1'}; d.update(defaults or {})
 z={'name':'wan','network':['wan','wan6'],'input':'REJECT','output':'ACCEPT','forward':'REJECT','masq':'1','fullcone':'1'}; z.update(zone or {})
 c={'defaults':d,'zone':[z]}; c.update(extra or {}); (fixtures/'uci/firewall.json').write_text(json.dumps(c))
 code='{% '+('global.system = () => 1; ' if unavailable else '')+'include("./root/usr/share/firewall4/main.uc", { getenv: (n) => n == "ACTION" ? "print" : null }); %}'
 p=subprocess.run([str(root/'staging_dir/hostpkg/bin/ucode'),'-S','-T,','-L./tests/lib','-L./root/usr/share/ucode','-D','MOCK_SEARCH_PATH='+json.dumps([str(fixtures),'./tests/mocks']),'-l','mocklib','-l','fw4','-'],cwd=src,input=code,text=True,capture_output=True)
 (T/(label+'.nft')).write_text(p.stdout); (T/(label+'.stderr')).write_text(p.stderr)
 assert p.returncode==0,(label,p.stderr)
 assert 'Syntax error' not in p.stderr,(label,p.stderr)
 return p.stdout,p.stderr

rows=[]
def check(label,expected,**args):
 s,e=render(label,**args)
 rules=[l for l in s.splitlines() if ' fullcone' in l]
 assert len(rules)==expected,(label,len(rules),e)
 for l in rules:assert 'meta l4proto { tcp, udp, udplite, sctp } fullcone' in l
 rows.append({'case':label,'fullcone_rules':len(rules)})
 return s,e
check('global-off',0,defaults={'fullcone':'0'})
check('zone-off',0,zone={'fullcone':'0'})
check('no-masquerade',0,zone={'masq':'0'})
check('ipv4-all',2)
check('ipv6-only',2,zone={'masq':'0','masq6':'1'})
check('dual-stack',4,zone={'masq6':'1'})
s,e=check('probe-failure',0,unavailable=True);assert 'masquerade' in s and 'disabling fullcone globally' in e
s,e=check('dnat-precedence',2,extra={'redirect':[{'name':'forward','src':'wan','src_dport':'2222','dest_ip':'192.0.2.2','dest_port':'22','proto':'tcp','target':'DNAT'}]});assert s.index('dnat 192.0.2.2:22')<s.index('NAT dstnat')
s,e=check('multiple-zones',2,extra={'zone':[{'name':'wan','network':['wan'],'masq':'1','fullcone':'1'},{'name':'lan','network':['lan'],'masq':'1','fullcone':'0'}]});assert 'lan IPv4 fullcone' not in s
s,e=check('restricted',2,zone={'masq_src':['192.0.2.0/24','!192.0.2.5'],'masq_dest':['!198.51.100.0/24']})
for l in s.splitlines():
 if 'NAT srcnat' in l:assert 'ip saddr 192.0.2.0/24' in l and 'ip saddr != 192.0.2.5' in l and 'ip daddr != 198.51.100.0/24' in l
 if 'NAT dstnat' in l:assert '192.0.2' not in l
# Removed UCI selection must never narrow the fixed set.
for i,protocols in enumerate([['udp'],['tcp','udp'],['icmp'],['!udp'],['!all'],['132'],['136'],['tcpudp'],['udp','icmp'],['!udp','tcp']]):
 check('obsolete-list-'+str(i),2,zone={'fullcone_proto':protocols})
s,e=check('helper-no-masq',0,zone={'masq':'0','auto_helper':'1'});assert 'helper_wan' in s
(T/'fw4-results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS 21 fw4 parser/template cases: fixed protocols, grouping, restrictions, precedence and fallback')
