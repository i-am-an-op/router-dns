#!/usr/bin/env python3
"""Execute captured hook control flow with paths mapped to disposable stubs.
This is a shell fixture, not APK installation or a router package test.
"""
import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Hooks(unittest.TestCase):
 def run_hook(self,disabled=False,instroot=False):
  with tempfile.TemporaryDirectory(prefix='dns-package-hook-') as d:
   r=Path(d);(r/'lib').mkdir();(r/'etc/init.d').mkdir(parents=True)
   log=r/'actions';functions='add_group_and_user() { echo identity >> "$ACTIONS"; }; default_postinst() { echo default_postinst >> "$ACTIONS"; };\n'
   (r/'lib/functions.sh').write_text(functions)
   service=r/'etc/init.d/dockerd';service.write_text('#!/bin/sh\necho "$1" >> "$ACTIONS"\n');service.chmod(0o755)
   original=(ROOT/'tests/fixtures/dockerd.post-install').read_text()
   pin=json.loads((ROOT/'tests/fixtures/SOURCE.json').read_text())['dockerd_post_install_sha256'];self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),pin)
   # Preserve control flow. Only absolute paths of the two OS dependencies move.
   script=original if instroot else original.replace('/lib/functions.sh',str(r/'lib/functions.sh')).replace('/etc/init.d/dockerd',str(service))
   f=r/'hook';f.write_text(script)
   p=subprocess.run(['/bin/sh',str(f)],env={'PATH':'/usr/bin:/bin','IPKG_INSTROOT':str(r) if instroot else '', 'IPKG_NO_SCRIPT':'1' if disabled else '0','ACTIONS':str(log)},capture_output=True,timeout=5)
   self.assertEqual(p.returncode,0,p.stderr);return log.read_text().splitlines() if log.exists() else []
 def test_normal_install_has_side_effects(self):self.assertEqual(self.run_hook(),['identity','default_postinst','enable','uciadd','start'])
 def test_no_script_executes_nothing(self):self.assertEqual(self.run_hook(disabled=True),[])
 def test_staged_root_does_not_start_host_service(self):self.assertEqual(self.run_hook(instroot=True),['identity','default_postinst'])
 def test_exact_installed_renderer_and_drift_rejection(self):
  with tempfile.TemporaryDirectory(prefix='dns-overlay-') as d:
   out=Path(d)/'overlay';src=ROOT/'tests/fixtures/openclash-installed'
   subprocess.run(['python3',str(ROOT/'scripts/render_openclash.py'),'--installed',str(src),'--output',str(out)],check=True,stdout=subprocess.DEVNULL)
   init=(out/'etc/init.d/openclash').read_text();subprocess.run(['sh','-n',str(out/'etc/init.d/openclash')],check=True)
   restore=init.split('revert_dnsmasq()\n{',1)[1].split('\n}',1)[0]
   self.assertIn('/usr/libexec/dnsctl protect',restore);self.assertNotIn('resolvfile',restore)
   self.assertIn('MIHOMO_MANAGED_DNS=1',init);self.assertIn('exec /usr/libexec/dns-core-guard',init)
   ctl=(out/'usr/lib/lua/luci/controller/openclash.lua').read_text();self.assertEqual(ctl.count('luci.http.status(409, "Managed configuration: stage off-router")'),11)
   model=(out/'usr/lib/lua/luci/model/cbi/openclash/config.lua').read_text();self.assertEqual(model.count('HTTP.status(409, "Managed configuration: stage off-router")'),2)
   # Corrupt captured source rejects without producing an accepted overlay.
   import shutil
   altered=Path(d)/'altered';shutil.copytree(src,altered);(altered/'etc/init.d/openclash').write_text('changed')
   p=subprocess.run(['python3',str(ROOT/'scripts/render_openclash.py'),'--installed',str(altered),'--output',str(Path(d)/'reject')],capture_output=True)
   self.assertNotEqual(p.returncode,0)
if __name__=='__main__':unittest.main()
