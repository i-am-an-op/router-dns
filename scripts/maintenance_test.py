#!/usr/bin/env python3
"""Exercise independent delivery logic with a local fixture HTTP server only."""
import datetime,json,threading,unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from unittest.mock import patch
import maintenance_watch as w
class TestMaintenance(unittest.TestCase):
 def test_unaccepted_operator_cannot_send(self):
  with self.assertRaises(ValueError):w.deliver({'healthy':False,'utc':'fixture'}, {'accepted':False})
 def test_delivery_and_failure(self):
  received=[]
  class Handler(BaseHTTPRequestHandler):
   def do_POST(self):
    received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))));self.send_response(204);self.end_headers()
   def log_message(self,*args):pass
  server=HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  import urllib.request
  real=urllib.request.build_opener
  class LocalFixture:
   def open(self,request,timeout):
    req=urllib.request.Request('http://127.0.0.1:'+str(server.server_port),data=request.data,headers=dict(request.headers),method='POST')
    return real().open(req,timeout=timeout)
  try:
   with patch.object(w.urllib.request,'build_opener',return_value=LocalFixture()):
    w.deliver({'healthy':False,'utc':'fixture','findings':['missed schedule'],'secret':'not allowed'}, {'accepted':True,'operator':'fixture only','webhook_url':'https://fixture.invalid'})
   self.assertEqual(len(received),1);self.assertNotIn('secret',received[0])
   with patch.object(w.urllib.request,'build_opener',side_effect=OSError('fixture failure')):
    with self.assertRaises(OSError):w.deliver({'healthy':False,'utc':'fixture'}, {'accepted':True,'operator':'fixture only','webhook_url':'https://fixture.invalid'})
  finally:server.shutdown();server.server_close()
if __name__=='__main__':unittest.main()
