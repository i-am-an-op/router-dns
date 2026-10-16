#!/usr/bin/env python3
"""Fetch a subscription to a new private file; never reload or contact a router.
Request JSON is private: {"url":"https://...","headers":{...}}. TLS verification
uses the system CA store. Redirects are rejected to avoid credential forwarding.
"""
import argparse,hashlib,json,os,ssl,urllib.request
from pathlib import Path
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('redirect requires review')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();os.umask(0o077)
 try:
  req=json.loads(a.request.read_text());url=req['url'];assert url.startswith('https://') and not a.output.exists()
  r=urllib.request.Request(url,headers=req.get('headers',{}));opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
  with opener.open(r,timeout=30) as response:data=response.read(16*1024*1024+1)
  assert 0<len(data)<=16*1024*1024
  with a.output.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'status':'unreviewed-staged-input','live_reload':False}))
 except Exception:raise SystemExit('Subscription fetch refused or failed; private request details suppressed')
if __name__=='__main__':main()
