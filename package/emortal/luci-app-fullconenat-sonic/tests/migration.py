#!/usr/bin/env python3
"""Test the actual install script with host UCI and isolated configurations.
Usage: migration.py REPOSITORY HOST_UCI OUTPUT_DIR
"""
from pathlib import Path
import itertools,os,subprocess,sys
root=Path(sys.argv[1]).resolve();binary=Path(sys.argv[2]).resolve();out=Path(sys.argv[3]).resolve();out.mkdir(parents=True,exist_ok=True)
functions=(root/'package/base-files/files/lib/functions.sh').read_text()
functions=functions[:functions.index('[ -z "$IPKG_INSTROOT" ] && [ -f /lib/config/uci.sh ]')]
functions+='\n'+(root/'package/system/uci/files/lib/config/uci.sh').read_text().replace('/sbin/uci','uci')+'\nLOAD_STATE=\n'
(out/'functions.sh').write_text(functions)
source=root/'package/emortal/luci-app-fullconenat-sonic/root/etc/uci-defaults/90-luci-app-fullconenat-sonic'
script=source.read_text().replace('. /lib/functions.sh','. "$TEST_FUNCTIONS"')
(out/'install.sh').write_text('uci() { "$TEST_UCI" -c "$UCI_CONFIG_DIR" -t "$TEST_DELTA" "$@"; }\n'+script)
count=0
for global_flag,zone_flag,mask6,legacy in itertools.product([None,'0','1'],[None,'0','1'],[None,'0','1'],[None,'1']):
 case=out/str(count);(case/'config').mkdir(parents=True);(case/'delta').mkdir()
 lines=['config defaults \'defaults\'']
 if global_flag is not None:lines.append(f" option fullcone '{global_flag}'")
 lines += ["config zone 'wan'"," option name 'wan'"," option masq '0'"," list fullcone_proto 'udp'"]
 for key,val in [('fullcone',zone_flag),('masq6',mask6),('fullcone6',legacy)]:
  if val is not None:lines.append(f" option {key} '{val}'")
 lines += ["config zone 'lan'"," option name 'lan'"," option fullcone '0'"," option masq6 '1'"]
 config=case/'config/firewall';config.write_text('\n'.join(lines)+'\n')
 for suffix in ['', '.apk-new','.apk-save']:(case/('config/fullconenat_sonic'+suffix)).write_text('obsolete\n')
 env=os.environ.copy();env.update(TEST_FUNCTIONS=str(out/'functions.sh'),TEST_UCI=str(binary),UCI_CONFIG_DIR=str(case/'config'),TEST_DELTA=str(case/'delta'))
 def run():subprocess.run(['bash',str(out/'install.sh')],env=env,check=True,capture_output=True)
 def get(name):
  r=subprocess.run([str(binary),'-c',str(case/'config'),'-t',str(case/'delta'),'-q','get','firewall.'+name],text=True,capture_output=True)
  return None if r.returncode else r.stdout.strip()
 run()
 enabled=global_flag!='0';fullcone='1' if legacy=='1' or zone_flag is None else zone_flag
 assert get('wan.fullcone')==fullcone
 assert get('wan.masq')==('1' if enabled and fullcone=='1' else '0')
 assert get('wan.masq6')==mask6
 assert get('lan.masq6')=='1' and get('lan.masq') is None
 assert get('wan.fullcone_proto') is None and get('wan.fullcone6') is None
 assert not list((case/'config').glob('fullconenat_sonic*'))
 first=config.read_bytes();run();assert first==config.read_bytes()
 count+=1
print(f'PASS {count} install/upgrade fixtures: real UCI, IPv6 preserved, legacy cleanup and idempotence')
