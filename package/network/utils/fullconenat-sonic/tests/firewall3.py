#!/usr/bin/env python3
"""Usage: firewall3.py REPOSITORY PREPARED_FIREWALL3 UCI_HEADERS OUTPUT_DIR."""
from pathlib import Path
import subprocess,sys
root,source,uci,out=[Path(p).resolve() for p in sys.argv[1:]]
out.mkdir(parents=True,exist_ok=True)
zones=(source/'zones.c').read_text()
code=zones[zones.index('static struct fw3_address *\nnext_addr'):zones.index('void\nfw3_print_zone_chains')]
(out/'fw3-zone-render.inc').write_text(code)
model=Path(__file__).with_name('firewall3-model.c')
subprocess.run(['gcc','-g','-fsanitize=address,undefined','-I'+str(root/'staging_dir/host/include'),'-I'+str(uci),'-I'+str(source),'-I'+str(out),str(model),'-o',str(out/'firewall3-model')],check=True)
with (out/'firewall3.log').open('w') as log:subprocess.run([str(out/'firewall3-model')],stdout=log,stderr=log,check=True,timeout=60)
print((out/'firewall3.log').read_text().strip())
