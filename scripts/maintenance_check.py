#!/usr/bin/env python3
"""Read-only maintenance heartbeat. Prints JSON and exits nonzero on gaps.

No messages, issues, workflow dispatch, update or deployment. Run on an
independent operator-controlled machine; GitHub cannot notice its own silence.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess

REPO='i-am-an-op/mihomo'
def assess(snapshot,now):
    problems=[]
    workflows={w['path']:w for w in snapshot['workflows']['workflows']}
    names=['upstream-sync.yml','downstream-ci.yml','downstream-release.yml','daily-security.yml']
    for name in names:
        w=workflows.get('.github/workflows/'+name)
        if not w or w.get('state')!='active': problems.append('workflow inactive or absent: '+name)
    for name,hours in [('upstream-sync.yml',36),('daily-security.yml',36),('downstream-ci.yml',168)]:
        runs=[r for r in snapshot['runs']['workflow_runs'] if r.get('path')=='.github/workflows/'+name and r.get('head_branch')=='dns-maintained']
        successes=[r for r in runs if r.get('conclusion')=='success']
        if not successes: problems.append('no observed successful run: '+name)
        else:
            last=max(dt.datetime.fromisoformat(r['updated_at'].replace('Z','+00:00')) for r in successes)
            if (now-last).total_seconds()>hours*3600:problems.append('success heartbeat overdue: '+name)
        for r in runs:
            created=dt.datetime.fromisoformat(r['created_at'].replace('Z','+00:00'))
            if r['status']!='completed' and (now-created).total_seconds()>3600:
                problems.append('run pending over one hour: '+str(r['id']))
        if runs:
            latest=max(runs,key=lambda r:r['created_at'])
            if latest['status']=='completed' and latest['conclusion']!='success':
                problems.append('latest run unsuccessful: '+name)
    if not snapshot.get('automated_security_fixes',{}).get('enabled'):
        problems.append('Dependabot security updates disabled or unverified')
    if snapshot.get('vulnerability_alerts_status')!=204:
        problems.append('Dependabot alerts not verified enabled')
    if snapshot['latest_upstream']['tag_name']!=snapshot['pin']['tag']:
        problems.append('new stable upstream requires review')
    if not snapshot.get('notification_test_completed',False):
        problems.append('external notification delivery has not been tested')
    if not snapshot.get('operator_acknowledged',False):
        problems.append('maintenance operator has not accepted responsibility')
    return {'checked_utc':now.isoformat(),'repository':REPO,'healthy':not problems,
        'findings':problems,'scope':'control-plane freshness; not vulnerability absence or router health',
        'automatic_deployment':False}

def api(path):
    p=subprocess.run(['gh','api',path],capture_output=True,text=True,timeout=40)
    if p.returncode:raise RuntimeError('GitHub read failed: '+path)
    return json.loads(p.stdout)

def collect(pin):
    if api('user').get('login') != 'i-am-an-op':
        raise RuntimeError('unexpected GitHub operator identity')
    # Explicit pagination avoids mistaking an old run on a later page for no run.
    runs=[]
    for page in range(1,6):
        batch=api(f'repos/{REPO}/actions/runs?per_page=100&page={page}')['workflow_runs']
        runs.extend(batch)
        if len(batch)<100:break
    check=subprocess.run(['gh','api','--include',f'repos/{REPO}/vulnerability-alerts'],capture_output=True,text=True,timeout=40)
    status=204 if check.returncode==0 and '204' in check.stdout.splitlines()[0] else None
    return {'pin':pin,'workflows':api(f'repos/{REPO}/actions/workflows'),
        'runs':{'workflow_runs':runs},'automated_security_fixes':api(f'repos/{REPO}/automated-security-fixes'),
        'vulnerability_alerts_status':status,'latest_upstream':api('repos/MetaCubeX/mihomo/releases/latest')}

def apply_operations(data, record, now):
    # This is an operator's review record, not proof of notification delivery.
    def fresh(name, days):
        try:
            stamp=dt.datetime.fromisoformat(record[name].replace('Z','+00:00'))
            return 0 <= (now-stamp).total_seconds() <= days*86400
        except (KeyError,TypeError,ValueError,AttributeError):
            return False
    data['operator_acknowledged']=bool(record.get('accepted') is True and record.get('operator') and fresh('reviewed_utc',90))
    data['notification_test_completed']=bool(record.get('notification_channel') and fresh('notification_test_utc',30))
    return data

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot',type=Path);p.add_argument('--pin',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--operations',type=Path,help='operator acknowledgement and dated delivery-test record')
    a=p.parse_args()
    try:
        data=json.loads(a.snapshot.read_text()) if a.snapshot else collect(json.loads(a.pin.read_text()))
        now=dt.datetime.now(dt.timezone.utc)
        if a.operations: data=apply_operations(data,json.loads(a.operations.read_text()),now)
        result=assess(data,now)
    except (OSError,RuntimeError,subprocess.TimeoutExpired,ValueError,KeyError,AttributeError) as e:
        result={'healthy':False,'findings':['monitor failed; human investigation required'],'automatic_deployment':False}
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['healthy'] else 2)
