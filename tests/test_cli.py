import threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from wordpress_auditor.auditor import Auditor, parse_burp

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok marker")
    def do_POST(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"<methodResponse><array><data/></array></methodResponse>")
    def log_message(self,*a): pass

class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s=HTTPServer(("127.0.0.1",0),H); threading.Thread(target=cls.s.serve_forever,daemon=True).start()
        cls.url=f"http://127.0.0.1:{cls.s.server_port}"
    @classmethod
    def tearDownClass(cls): cls.s.shutdown()
    def test_burp(self):
        u,h,b=parse_burp("GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n"); self.assertIn("127.0.0.1",u)
    def test_audit(self):
        r=Auditor(self.url).discover("marker"); self.assertTrue(r); self.assertTrue(any("marker" in x.detail for x in r))
if __name__=="__main__": unittest.main()
