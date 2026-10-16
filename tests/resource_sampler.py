#!/usr/bin/env python3
"""Read-only bounded resolver/runtime resource samples. Never reads command args."""
import argparse,json,os,time,signal
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seconds',type=int,default=30);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert 1<=a.seconds<=120 and not a.output.exists()
rows=[];start=time.monotonic();running=True
def stop(*args):
 global running
 running=False
signal.signal(signal.SIGTERM,stop)
while running and time.monotonic()-start<a.seconds:
 sample=[]
 for path in Path('/proc').glob('[0-9]*'):
  try:
   name=(path/'comm').read_text().strip()
   if name not in ['coredns','mihomo','clash','clash_meta','unbound','qemu-aarch64','dockerd','containerd'] and not name.startswith('containerd-shim'):continue
   stat=(path/'stat').read_text().rsplit(')',1)[1].split();mem={}
   try:
    for line in (path/'smaps_rollup').read_text().splitlines():
     if line.startswith(('Pss:','Rss:')):key,value,*_=line.split();mem[key.rstrip(':')+'_kib']=int(value)
   except PermissionError:mem['pss_permission_denied']=True
   sample.append({'pid':int(path.name),'name':name,'cpu_ticks':int(stat[11])+int(stat[12]),**mem})
  except (FileNotFoundError,ProcessLookupError,PermissionError):pass
 rows.append({'elapsed':time.monotonic()-start,'processes':sample});time.sleep(.5)
a.output.write_text(json.dumps({'scope':'read-only process samples; shared pages use PSS when available; emulation/daemon effects must be stated','clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),'samples':rows},indent=2)+'\n')
