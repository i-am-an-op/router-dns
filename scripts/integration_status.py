#!/usr/bin/env python3
"""Read-only freshness checks for the integration repository; sends nothing."""
import datetime as dt,json
from maintenance_check import api
REPO='i-am-an-op/router-dns'
def assess(data,now):
 issues=[];workflows={x['path']:x for x in data['workflows']['workflows']}
 for name,hours in [('ci.yml',168),('daily-security.yml',36)]:
  path='.github/workflows/'+name
  if workflows.get(path,{}).get('state')!='active':issues.append('integration workflow absent/inactive: '+name)
  runs=[r for r in data['runs']['workflow_runs'] if r.get('path')==path and r.get('head_branch')=='main']
  good=[r for r in runs if r.get('conclusion')=='success']
  if not good:issues.append('no integration successful run: '+name)
  else:
   last=max(dt.datetime.fromisoformat(r['updated_at'].replace('Z','+00:00')) for r in good)
   if (now-last).total_seconds()>hours*3600:issues.append('integration success overdue: '+name)
  if runs:
   last=max(runs,key=lambda x:x['created_at']);age=(now-dt.datetime.fromisoformat(last['created_at'].replace('Z','+00:00'))).total_seconds()
   if last['status']=='completed' and last.get('conclusion')!='success':issues.append('integration latest run failed: '+name)
   if last['status']!='completed' and age>3600:issues.append('integration workflow pending over one hour: '+name)
 if not data['security_fixes'].get('enabled'):issues.append('integration security updates disabled')
 return issues
def collect():
 runs=[]
 for page in range(1,6):
  batch=api(f'repos/{REPO}/actions/runs?per_page=100&page={page}')['workflow_runs'];runs.extend(batch)
  if len(batch)<100:break
 return {'workflows':api(f'repos/{REPO}/actions/workflows'),'runs':{'workflow_runs':runs},'security_fixes':api(f'repos/{REPO}/automated-security-fixes')}
