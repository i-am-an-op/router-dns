#!/usr/bin/env python3
"""Independent workstation check with optional explicitly configured delivery.
Default is status-file only. No recipient/operator is invented or activated.
"""
import argparse,datetime,json,os,subprocess,urllib.request
from pathlib import Path

def deliver(record,operations):
 if operations.get('accepted') is not True or not operations.get('operator'):
  raise ValueError('No accepted operator')
 url=operations.get('webhook_url','')
 if not url.startswith('https://'):raise ValueError('Accepted HTTPS delivery endpoint required')
 # No repository secrets, profile values or environment are put in notifications.
 body=json.dumps({'project':'router-dns','healthy':record['healthy'],'utc':record['utc'],'findings':record.get('findings',[])}).encode()
 req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST')
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise ValueError('Redirect refused')
 with urllib.request.build_opener(NoRedirect()).open(req,timeout=10) as r:
  if r.status//100!=2:raise ValueError('Delivery not acknowledged')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--operations',type=Path);p.add_argument('--pin',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--notify',action='store_true');a=p.parse_args();os.umask(0o077)
 cmd=['python3',str(Path(__file__).with_name('maintenance_check.py')),'--output',str(a.output),'--pin',str(a.pin)]
 if a.operations:cmd+=['--operations',str(a.operations)]
 try:
  r=subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
  if r.returncode not in (0,2):raise ValueError('checker failed')
  record=json.loads(a.output.read_text())
 except (OSError,ValueError,subprocess.TimeoutExpired):
  r=subprocess.CompletedProcess(cmd,124)
  record={'healthy':False,'findings':['Checker failed or timed out; investigate credentials/network/scheduler']}
 try:
  from integration_status import assess,collect
  findings=assess(collect(),datetime.datetime.now(datetime.timezone.utc))
 except Exception:findings=['Integration maintenance checker failed; investigate']
 record.setdefault('findings',[]).extend(findings)
 record['healthy']=bool(record.get('healthy')) and not findings
 record['utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();record['checker_exit']=r.returncode;record['notification']='not-configured'
 if a.notify:
  try:deliver(record,json.loads(a.operations.read_text()));record['notification']='acknowledged'
  except Exception:record['notification']='failed-or-unconfigured'
 with a.output.open('w') as f:json.dump(record,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'healthy':record.get('healthy',False),'notification':record['notification']}))
 raise SystemExit(0 if record.get('healthy') else 1)
if __name__=='__main__':main()
