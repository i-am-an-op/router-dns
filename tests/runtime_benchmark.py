#!/usr/bin/env python3
"""Bounded, seeded query workload for either candidate. Does not change services.
Records response classes and latency/errors, not a claim of DNS truth. Supply
an identical corpus/seed to both methods; run cold/warm phases separately.
"""
import argparse,concurrent.futures,hashlib,json,random,statistics,time
from pathlib import Path
import dns.message,dns.query

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--address',required=True);p.add_argument('--port',type=int,default=6053);p.add_argument('--corpus',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--requests',type=int,default=200);p.add_argument('--concurrency',type=int,default=4);p.add_argument('--tcp',action='store_true');p.add_argument('--seed',type=int,default=1);a=p.parse_args()
 assert 1<=a.requests<=2000 and 1<=a.concurrency<=16 and not a.output.exists()
 corpus=[x.split() for x in a.corpus.read_text().splitlines() if x.strip() and not x.startswith('#')];rng=random.Random(a.seed);work=[rng.choice(corpus) for _ in range(a.requests)]
 def one(row):
  started=time.monotonic();result={'name':row[0],'type':row[1]}
  try:
   q=dns.message.make_query(row[0],row[1],want_dnssec=True);r=(dns.query.tcp if a.tcp else dns.query.udp)(q,a.address,port=a.port,timeout=5)
   result.update(rcode=r.rcode(),answer_rrsets=len(r.answer),flags=r.flags,bytes=len(r.to_wire()))
  except Exception as e:result['error']=type(e).__name__
  result['ms']=(time.monotonic()-started)*1000;return result
 start=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(a.concurrency) as pool:rows=list(pool.map(one,work))
 elapsed=time.monotonic()-start;lat=sorted(x['ms'] for x in rows)
 result={'scope':'bounded client workload; no service mutation; not proof of response correctness','requests':a.requests,'concurrency':a.concurrency,'seed':a.seed,'tcp':a.tcp,'address':a.address,'port':a.port,'corpus_sha256':hashlib.sha256(a.corpus.read_bytes()).hexdigest(),'elapsed_seconds':elapsed,'completed_per_second':a.requests/elapsed,'transport_errors':sum('error' in x for x in rows),'latency_ms':{p:lat[min(len(lat)-1,int(len(lat)*q))] for p,q in [('p50',.5),('p95',.95),('p99',.99)]},'rows':rows}
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'}))
if __name__=='__main__':main()
