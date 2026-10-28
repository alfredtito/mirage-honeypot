#!/usr/bin/env python3
"""Scripted attacker traffic for YOUR OWN Mirage instance. Standard library only.

Sends typical scanner/crawler/brute-force-style requests so you have realistic sessions to analyse,
and so the same traffic can be replayed against mirage mode and static mode for a fair comparison.
Only run this against a honeypot you own.

    python3 scripts/simulate_scan.py http://127.0.0.1:8080 --profile all
    python3 scripts/simulate_scan.py http://192.168.x.1:8080 --profile crawler --max 40
"""
import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UAS = {
    "recon": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "scanner": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
    "brute": "python-requests/2.31.0",
    "crawler": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/admin", "/administrator", "/login", "/wp-login.php", "/phpmyadmin/",
    "/.env", "/.git/config", "/backup.zip", "/config.php", "/server-status", "/api/v1/users",
    "/api/v1/shipments", "/uploads/", "/info.php", "/cgi-bin/", "/console", "/db.sql", "/test",
]
PROBES = ["?id=1'", "?file=../../../../etc/passwd", "?q=<script>alert(1)</script>"]
CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "toor"),
         ("administrator", "Welcome1"), ("test", "test")]
HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.I)


class Runner:
    def __init__(self, base, ua, delay, timeout, budget):
        self.base, self.ua, self.delay, self.timeout, self.left = base.rstrip("/"), ua, delay, timeout, budget
        self.count = 0

    def req(self, method, path, data=None):
        if self.left <= 0:
            return None
        self.left -= 1
        self.count += 1
        url = self.base + urllib.parse.quote(path, safe="/?=&%'<>:.-_~,;()")
        headers = {"User-Agent": self.ua, "Accept": "*/*"}
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        t0 = time.time()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, method=method, headers=headers),
                                        timeout=self.timeout) as r:
                status, text = r.status, r.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read(200000).decode("utf-8", "replace")
        except Exception as e:  # timeout, refused, reset
            status, text = 0, ""
            print(f"  ERR  {method} {path}: {type(e).__name__}")
        print(f"  {status:>3}  {len(text):>6}B  {time.time()-t0:5.1f}s  {method} {path}")
        time.sleep(self.delay)
        return status, text


def run_recon(r):
    r.req("HEAD", "/")
    r.req("OPTIONS", "/")
    for p in COMMON_PATHS[:10]:
        r.req("GET", p)


def run_scanner(r):
    found = []
    for p in COMMON_PATHS:
        res = r.req("GET", p)
        if res and res[0] in (200, 401, 403):
            found.append(p)
    for p in (found or ["/"])[:3]:
        for q in PROBES:
            r.req("GET", p + q)
    r.req("GET", "/..%2f..%2f..%2fetc/passwd")


def run_brute(r):
    for target in ("/login", "/admin"):
        res = r.req("GET", target)
        if res and res[0] in (200, 401, 403):
            for user, pw in CREDS:
                r.req("POST", target, {"username": user, "password": pw})
            break


def run_crawler(r):
    seen, queue = set(), ["/"]
    while queue and r.left > 0:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        res = r.req("GET", path)
        if not res or res[0] != 200:
            continue
        for href in HREF.findall(res[1]):
            u = urllib.parse.urlparse(urllib.parse.urljoin(r.base + path, href))
            if u.netloc == urllib.parse.urlparse(r.base).netloc and u.path not in seen:
                queue.append(u.path + (f"?{u.query}" if u.query else ""))


PROFILES = {"recon": run_recon, "scanner": run_scanner, "brute": run_brute, "crawler": run_crawler}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="e.g. http://127.0.0.1:8080 (a honeypot YOU own)")
    ap.add_argument("--profile", default="all", choices=[*PROFILES, "all"])
    ap.add_argument("--max", type=int, default=40, help="max requests per profile")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--tag", default="", help="suffix added to the User-Agent so repeated runs are separate sessions")
    a = ap.parse_args()
    names = list(PROFILES) if a.profile == "all" else [a.profile]
    for n in names:
        print(f"== {n} ({UAS[n][:50]}...)")
        r = Runner(a.target, UAS[n] + (f" {a.tag}" if a.tag else ""), a.delay, a.timeout, a.max)
        PROFILES[n](r)
        print(f"   {r.count} requests\n")


if __name__ == "__main__":
    sys.exit(main())
