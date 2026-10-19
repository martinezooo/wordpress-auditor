import argparse, json, sys
from .auditor import Auditor, parse_burp

def main(argv=None):
    p=argparse.ArgumentParser(description="bounded WordPress visibility auditor")
    g=p.add_mutually_exclusive_group(required=True); g.add_argument("--url"); g.add_argument("--request", help="file containing Burp raw request")
    p.add_argument("--cookie"); p.add_argument("--header", action="append", default=[]); p.add_argument("--proxy")
    p.add_argument("--marker"); p.add_argument("--post-comment", action="store_true")
    p.add_argument("--format", choices=("json","csv","md"), default="json"); p.add_argument("--output")
    a=p.parse_args(argv)
    headers={k:v for x in a.header for k,v in [x.split(":",1)]}
    if a.request:
        raw=open(a.request, encoding="utf-8").read(); url,bh,_=parse_burp(raw); headers={**bh,**headers}
    else: url=a.url
    results=Auditor(url,headers,a.cookie,a.proxy).discover(a.marker,a.post_comment)
    rows=[r.__dict__ for r in results]
    if a.format=="json": out=json.dumps(rows, indent=2)
    elif a.format=="csv":
        s=__import__("io").StringIO(); w=__import__("csv").DictWriter(s,fieldnames=["name","url","status","visibility","detail"]); w.writeheader(); w.writerows(rows); out=s.getvalue()
    else: out="| Name | URL | Status | Visibility | Detail |\n|---|---|---:|---|---|\n"+"".join(f"| {r['name']} | {r['url']} | {r['status']} | {r['visibility']} | {r['detail']} |\n" for r in rows)
    if a.output: open(a.output,"w",encoding="utf-8").write(out)
    else: print(out)
