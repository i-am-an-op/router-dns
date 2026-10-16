#!/usr/bin/env python3
"""Render a complete private managed profile from reviewed runtime + subscription.
Preserves existing application rules/proxies/groups. Never prints config values.
"""
import argparse,copy,importlib.util,json,os
from pathlib import Path
import yaml
HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('overlay',HERE/'proposals/render_private_overlay.py');overlay=importlib.util.module_from_spec(spec);spec.loader.exec_module(overlay)
p=argparse.ArgumentParser(description=__doc__)
for n in ['runtime','subscription','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--transport',choices=['shared','separate'],required=True);a=p.parse_args();os.umask(0o077)
runtime=yaml.safe_load(a.runtime.read_text());subscription=yaml.safe_load(a.subscription.read_text());delta=overlay.render(runtime,subscription)
profile=copy.deepcopy(runtime);profile['dns']=delta['dns!'];profile['ipv6']=True
# These global mutation endpoints are guarded by the managed frontend. Background
# geodata auto-update is disabled explicitly; dynamic proxy node refresh remains.
profile['geodata-auto-update']=False
listeners=delta['listeners+'] if a.transport=='shared' else [x for x in delta['listeners+'] if x['name']=='dns-mt5000-local']
for key,added in [('listeners',listeners),('proxies',delta['proxies+'] if a.transport=='shared' else []),('proxy-groups',delta['proxy-groups+'] if a.transport=='shared' else [])]:
 existing=profile.setdefault(key,[]);names={x['name'] for x in existing}
 if any(x['name'] in names for x in added):raise SystemExit('DNS addition collides with an existing name; review required')
 existing.extend(added)
assert profile.get('rules')==runtime.get('rules')
for key in ['proxies','proxy-groups']:
 assert profile[key][:len(runtime.get(key,[]))]==runtime.get(key,[])
with a.output.open('x') as f:yaml.safe_dump(profile,f,allow_unicode=True,sort_keys=False)
print(json.dumps({'rendered':True,'existing_application_rules_proxies_groups_preserved':True,'transport':a.transport,'deployment_authorized':False}))
