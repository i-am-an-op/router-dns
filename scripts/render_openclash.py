#!/usr/bin/env python3
"""Render the exact captured 0.48.002/local-init integration; no remote actions."""
import argparse, difflib, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
PINS={
 'etc/init.d/openclash':'df9ce3f7967837d7a9d03e418b16683404ce079bf5c537dc4a1e6d837bc3ddd4',
 'usr/share/openclash/openclash_core.sh':'66d7130b23947a23d255ed2d57f2da0bb3feabbae1fd88af4f81d3de746e6189',
 'usr/share/openclash/openclash_update.sh':'391f14bd749062975a98a10fb7aea3b843cad3544a7b52313ed9d846463dca6c',
 'usr/lib/lua/luci/model/cbi/openclash/config.lua':'0bcc20431e7a50dfa4c7a1a9eb3381690a212a57b55432c89aff03fadc888be2',
 'usr/lib/lua/luci/controller/openclash.lua':'5eeeacd451a5604064a4dd4c7cf4d006b2f83fcc15b65e10d8db1bb3bc47a341'}
def once(s,a,b):
 if s.count(a)!=1:raise ValueError('source context differs; review required')
 return s.replace(a,b,1)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--installed',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
 records=[];patch=[]
 for rel,pin in PINS.items():
  old=(a.installed/rel).read_text();assert hashlib.sha256(old.encode()).hexdigest()==pin,rel
  s=old
  if rel=='etc/init.d/openclash':
   for f in ['start_service','restart','do_run_file']:
    s=once(s,f+'()\n{\n',f+'()\n{\n   /usr/libexec/dns-core-guard preflight || return 78\n')
   begin=s.index('      # Check instead of restart',s.index('start_service()'))
   end=s.index('      LOG_OUT "Step 4:',begin)
   s=s[:begin]+'''      # Rendering occurs off-router; application routing is reviewed as a whole.
      get_config
      CONFIG_FILE=$(/usr/libexec/dnsctl guard path) || return 78
      TMP_CONFIG_FILE="$CONFIG_FILE"
      RAW_CONFIG_FILE="$CONFIG_FILE"
      QUICK_START=true
      do_run_mode
      do_run_file "$RAW_CONFIG_FILE" || return 78

'''+s[end:]
   s=once(s,'start_run_core()\n{\n','start_run_core()\n{\n   /usr/libexec/dns-core-guard config "$CONFIG_FILE" || return 78\n')
   s=once(s,'exec $CLASH -d $CLASH_CONFIG -f','exec /usr/libexec/dns-core-guard exec -d $CLASH_CONFIG -f')
   s=once(s,'   procd_append_param env SKIP_SYSTEM_IPV6_CHECK=1\n','   procd_append_param env SKIP_SYSTEM_IPV6_CHECK=1\n   procd_append_param env MIHOMO_MANAGED_DNS=1\n')
   s=once(s,'      start_run_core\n\n','      start_run_core || return 78\n\n')
   b=s.index('revert_dnsmasq()\n{');e=s.index('\n}',b)+2
   s=s[:b]+'''revert_dnsmasq()
{
   # Never restore ISP/WAN/plain fallback on stop or failed startup.
   /usr/libexec/dnsctl protect || return 78
}'''+s[e:]
  elif rel.endswith('model/cbi/openclash/config.lua'):
   s=once(s,'\tfunction(meta, chunk, eof)\n','\tfunction(meta, chunk, eof)\n\t\tHTTP.status(409, "Managed configuration: stage off-router")\n\t\tdo return end\n')
   s=once(s,'sev.write = function(self, section, value)\n','sev.write = function(self, section, value)\nHTTP.status(409, "Managed configuration: stage off-router")\ndo return end\n')
  elif rel.endswith('controller/openclash.lua'):
   for f in ['action_update_config','action_restore_config','action_switch_config','action_upload_config','action_restore_backup','action_config_file_save','action_add_subscription','action_upload_overwrite','action_add_age_config','action_coreupdate','action_opupdate']:
    s=once(s,'function '+f+'()\n','function '+f+'()\n    luci.http.status(409, "Managed configuration: stage off-router")\n    do return end\n')
  else:s=(HERE/'runtime/managed-update-block.sh').read_text()
  dest=a.output/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(s);dest.chmod(0o644 if rel.endswith('.lua') else 0o755)
  records.append({'path':rel,'before_sha256':pin,'after_sha256':hashlib.sha256(s.encode()).hexdigest()})
  patch.extend(difflib.unified_diff(old.splitlines(True),s.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
 # The subscription updater must never overwrite a running managed profile.
 rel='usr/share/openclash/openclash.sh';old=(a.installed/rel).read_bytes();dest=a.output/rel;dest.write_bytes((HERE/'runtime/managed-update-block.sh').read_bytes());dest.chmod(0o755)
 records.append({'path':rel,'before_sha256':hashlib.sha256(old).hexdigest(),'after_sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
 (a.output/'patch.diff').write_text(''.join(patch));(a.output/'overlay.json').write_text(json.dumps({'package':'0.48.002','upstream':'e553e82e01c697aefbe1555261a503f425e00ccd','init':'captured local modification, not tag source','files':records,'deployed':False},indent=2)+'\n')
 print(json.dumps({'files':len(records),'deployed':False}))
if __name__=='__main__':main()
