#!/usr/bin/env python3
"""Execute pilot shell flow with explicit OS/service stubs, never a real router.
Tests ownership, cleanup, syntax/state separation and watchdog decisions. Does
not claim to test procd, mounts, Engine or actual 900-second elapsed duration.
"""
import json,os,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
class Pilot(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='dns-pilot-fixture-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.base=self.root/'base';self.base.mkdir();self.run=self.root/'run';self.run.mkdir();self.stub=self.root/'stubs';self.stub.mkdir();self.log=self.root/'calls';self.uptime=self.root/'uptime';self.uptime.write_text('100.0 0\n')
  script=(HERE/'runtime/pilot.sh').read_text().replace('/opt/dns-evaluation/20261016-rc1',str(self.base)).replace('/var/run/',str(self.run)+'/').replace('/proc/uptime',str(self.uptime))
  self.script=self.base/'pilot.sh';self.script.write_text(script);self.script.chmod(0o755)
  for mode in ['native','compose']:
   for lane in ['g1','g2','g3','d1']:
    p=self.base/f'state-{mode}/anchors/{lane}/root.key';p.parent.mkdir(parents=True);p.write_text('test-only anchor')
   (self.base/f'state-{mode}/mihomo').mkdir()
  (self.base/'config').mkdir();(self.base/'bin').mkdir();(self.base/'root/lib').mkdir(parents=True);(self.base/'native-services.json').write_text('{"name":"dns-evaluation","instances":{}}');(self.base/'aux-image-id').write_text('sha256:testaux');(self.base/'coredns-image-id').write_text('sha256:testcore')
  self.env=dict(os.environ,PATH=str(self.stub)+':'+os.environ['PATH'],PILOT_FIXTURE_LOG=str(self.log),PILOT_FIXTURE_BASE=str(self.base),PILOT_FIXTURE_UPTIME=str(self.uptime))
  common='#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$PILOT_FIXTURE_LOG"\n'
  scripts={'sha256sum':'exit 0','chronyc':'exit 0','awk':'exit 1','sleep':'if [ "${FIXTURE_DEADLINE:-0}" = 1 ]; then printf "1001.0 0\\n" > "$PILOT_FIXTURE_UPTIME"; fi', 'ubus':'exit 0','docker':'case "$*" in *" up "*) [ "${FIXTURE_UP_FAIL:-0}" != 1 ];; *) exit 0;; esac','mount':'[ "${FIXTURE_MOUNT_FAIL:-0}" != 1 ] || exit 1\nrmdir "$4"\nln -s "$3" "$4"','umount':'rm "$1"\nmkdir "$1"'}
  # mount --bind source target: shell positional arguments are $1/$2/$3.
  scripts['mount']=scripts['mount'].replace('"$4"','"$3"').replace('ln -s "$3" "$3"','ln -s "$2" "$3"')
  for n,body in scripts.items():p=self.stub/n;p.write_text(common+body+'\n');p.chmod(0o755)
  for rel,body in [('bin/mihomo','exit 0'),('bin/dnsctl','[ "${FIXTURE_PROBE_FAIL:-0}" != 1 ]'),('root/lib/ld-musl-aarch64.so.1','case "$*" in *" -o interface "*) exit 0;; *) exit 78;; esac')]:p=self.base/rel;p.write_text(common+body+'\n');p.chmod(0o755)
 def call(self,op,mode='native',ok=True,**env):
  r=subprocess.run([str(self.script),op,mode],env=dict(self.env,**env),capture_output=True,text=True,timeout=10)
  self.assertEqual(r.returncode==0,ok,r.stderr);return self.log.read_text() if self.log.exists() else ''
 def mark(self,mode):
  (self.run/'dns-evaluation-mode').write_text(mode+'\n');(self.run/'dns-evaluation-start-attempted').touch()
 def test_preflight_syntax_without_mounted_state(self):
  log=self.call('preflight');self.assertEqual(log.count('-o interface'),4);self.assertFalse((self.base/'state').exists())
 def test_missing_anchor_refused(self):
  (self.base/'state-native/anchors/g1/root.key').unlink();self.call('preflight',ok=False)
 def test_native_start_stop_and_idempotent_stop(self):
  log=self.call('start');self.assertIn('dns-evaluation-watchdog',log);self.assertIn('wait-probe readiness.json 60',log);self.assertTrue((self.base/'state').is_symlink());self.call('stop');self.call('stop');self.assertFalse((self.run/'dns-evaluation-mode').exists());self.assertFalse((self.base/'state').is_symlink())
 def test_compose_start_stop(self):
  log=self.call('start','compose');self.assertIn('--pull never',log);self.assertIn('dns-evaluation-watchdog',log);self.call('stop','compose')
 def test_failed_native_readiness_cleans_owned_state(self):
  self.call('start',ok=False,FIXTURE_PROBE_FAIL='1');self.assertFalse((self.run/'dns-evaluation-mode').exists());self.assertFalse((self.base/'state').is_symlink())
 def test_failed_compose_start_cleans(self):
  log=self.call('start','compose',ok=False,FIXTURE_UP_FAIL='1');self.assertIn('down --timeout 10',log);self.assertFalse((self.run/'dns-evaluation-mode').exists())
 def test_failed_mount_cleans_marker(self):
  self.call('start',ok=False,FIXTURE_MOUNT_FAIL='1');self.assertFalse((self.run/'dns-evaluation-mode').exists())
 def test_other_owner_is_not_stopped(self):
  self.mark('compose');log=self.call('stop',ok=False);self.assertNotIn('delete',log);self.assertTrue((self.run/'dns-evaluation-mode').exists())
 def test_watch_deadline_requests_stop(self):
  self.mark('native');log=self.call('watch',FIXTURE_DEADLINE='1');self.assertIn('delete',log);self.assertFalse((self.run/'dns-evaluation-mode').exists())
 def test_watch_three_unhealthy_checks_stops(self):
  self.mark('compose');log=self.call('watch','compose',FIXTURE_PROBE_FAIL='1');self.assertEqual(log.count('wait-probe readiness.json 5'),3);self.assertIn('down --timeout 10',log);self.assertFalse((self.run/'dns-evaluation-mode').exists())
if __name__=='__main__':unittest.main()
