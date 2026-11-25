#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

MODES = ("basic", "advanced-exact", "advanced-wildcard")

# Compact PSL stand-in (multi-part suffixes).
MULTI = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk net.uk com.au net.au org.au edu.au gov.au
    co.nz org.nz net.nz co.jp or.jp ne.jp go.jp ac.jp co.kr or.kr go.kr ac.kr
    com.br net.br org.br gov.br com.mx org.mx gob.mx co.za org.za web.za
    com.cn net.cn org.cn com.tw org.tw com.hk org.hk com.sg com.tr com.ar com.pl
    com.ru net.ru org.ru pp.ru com.ua co.in firm.in gen.in ind.in net.in org.in
    com.pt br.com cn.com de.com eu.com gb.com gr.com hu.com jpn.com kr.com
    no.com qc.com ru.com sa.com se.com uk.com us.com uy.com za.com co.com
    com.de gb.net us.org ae.org
    """.split()
)
BARE = frozenset(
    """
    com net org io co app dev xyz info biz me tv cc ru ua uk de fr es it nl eu
    us ca au nz jp kr cn tw hk sg in br mx za pl tr ar pt gov edu mil int arpa
    cloud local internal localhost test example invalid
    """.split()
) | MULTI

SERVICE = tuple(
    """
    edgekey.net edgesuite.net akamaiedge.net akamai.net akamaitechnologies.com
    cloudfront.net amazonaws.com awsglobalaccelerator.com elasticbeanstalk.com
    cloudflare.com cloudflare.net cloudflare-dns.com fastly.net fastlylb.net
    herokuapp.com herokudns.com azurewebsites.net azurefd.net trafficmanager.net
    googleusercontent.com googleapis.com ghs.googlehosted.com impervadns.net
    incapdns.net sucuri.net
    """.split()
)


def err(*a):
    print(*a, file=sys.stderr)


def die(msg: str, code: int = 2) -> None:
    err(msg)
    raise SystemExit(code)


def truthy(v: str | None) -> bool:
    return bool(v) and v.strip().lower() in {"1", "true", "yes", "y"}


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def as_ip(v: str) -> str | None:
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


def parse_ips(raw: str | None) -> list[str]:
    if not raw or not (t := raw.strip()) or t.lower() == "null":
        return []
    if t.startswith("["):
        try:
            data = json.loads(t)
        except json.JSONDecodeError:
            return []
        return [str(x).strip() for x in data if x not in (None, "")] if isinstance(data, list) else []
    return [t]


def normalize_host(value: str) -> str | None:
    h = value.strip().lower().rstrip(".")
    if not h or h == "null":
        return None
    if "://" in h:
        h = (urlparse(h).hostname or "").lower().rstrip(".")
    if not h:
        return None
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not is_ip(h) and h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    if is_ip(h):
        return as_ip(h)
    if not re.fullmatch(r"[a-z0-9._-]+", h) or ("." not in h and h != "localhost"):
        return None
    return h


def is_service(host: str) -> bool:
    return not is_ip(host) and any(host == s or host.endswith("." + s) for s in SERVICE)


def registrable(host: str) -> str | None:
    if is_ip(host):
        return None
    parts = [p for p in host.lower().rstrip(".").split(".") if p]
    if len(parts) < 2:
        return None
    last2 = ".".join(parts[-2:])
    if last2 in MULTI:
        if len(parts) < 3:
            return None
        cand = ".".join(parts[-3:])
    else:
        cand = last2
    if cand in BARE or cand in MULTI or len(cand.split(".")) < 2:
        return None
    return cand


def host_re(value: str) -> str:
    return f"^{re.escape(value)}$"


def sort_ips(ips: set[str]) -> list[str]:
    return sorted(ips, key=lambda x: (":" in x, ipaddress.ip_address(x)))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="httpx-to-burp",
        description="Convert httpx CSV into a Burp Suite Target Scope .txt file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""modes:
  basic               plain hosts + IPs
  advanced-exact      regex ^host$ + IPs
  advanced-wildcard   regex ^(.*\\.)?apex$ + IPs

import in Burp (Target > Scope):
  1. for advanced-* enable "Use advanced scope control"
  2. click Load ...
  3. select the .txt file

examples:
  %(prog)s -i httpx-result.csv -m basic
  %(prog)s -i httpx-result.csv -m advanced-wildcard
  %(prog)s -i httpx-result.csv -m advanced-exact --hosts-only
  %(prog)s -i httpx-result.csv -m basic -o my-scope.txt
""",
    )
    p.add_argument("-i", "--input", metavar="FILE", required=True, help="httpx CSV path, or '-' for stdin")
    p.add_argument("-m", "--mode", metavar="MODE", required=True, choices=MODES, help="scope mode (see below)")
    p.add_argument("-o", "--output", metavar="FILE", default=None, help="output path (default: burp-scope.txt)")
    p.add_argument("--skip-cdn", action="store_true", help="skip rows marked as CDN/WAF by httpx")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--hosts-only", action="store_true", help="emit hosts only")
    g.add_argument("--ips-only", action="store_true", help="emit IPs only")
    p.add_argument("-v", "--verbose", action="store_true", help="print skipped rows to stderr")
    return p.parse_args()


def out_path(output: str | None) -> Path:
    path = Path(output) if output else Path("burp-scope.txt")
    suf = path.suffix.lower()
    if suf not in ("", ".txt"):
        die(f"error: output must be .txt, got '{suf}'")
    return path if suf else path.with_suffix(".txt")


def collect(reader: csv.DictReader, skip_cdn: bool, verbose: bool):
    if not set(reader.fieldnames or []) & {"host", "url", "input"}:
        die("error: not an httpx CSV (need host/url/input)")

    hosts: set[str] = set()
    ips: set[str] = set()
    st: dict[str, int] = defaultdict(int)

    def skip(key: str, msg: str):
        st[key] += 1
        if verbose:
            err(msg)

    for i, row in enumerate(reader, 2):
        st["rows"] += 1
        if truthy(row.get("failed")):
            skip("skipped_failed", f"skip line {i}: failed")
            continue
        if skip_cdn and (
            truthy(row.get("cdn"))
            or ((row.get("cdn_name") or "").strip().lower() not in ("", "null"))
        ):
            skip("skipped_cdn", f"skip line {i}: cdn")
            continue

        host = None
        cands = [row.get("host") or "", row.get("input") or ""]
        if row.get("url"):
            cands.append(urlparse(row["url"]).hostname or "")
        for c in cands:
            host = normalize_host(c)
            if host:
                break
        if not host:
            skip("skipped_bad", f"skip line {i}: no host")
            continue

        if is_ip(host):
            ips.add(host)
        elif is_service(host):
            skip("skipped_service", f"skip host {host}: service zone")
        else:
            hosts.add(host)

        for raw in (row.get("host_ip"), row.get("a"), row.get("aaaa")):
            for item in parse_ips(raw):
                if ip := as_ip(item):
                    ips.add(ip)

    return hosts, ips, dict(st)


def build(
    mode: str,
    hosts: set[str],
    ips: set[str],
    hosts_only: bool,
    ips_only: bool,
    verbose: bool,
) -> tuple[list[str], dict[str, int]]:
    host_list = [] if ips_only else sorted(hosts)
    ip_list = [] if hosts_only else sort_ips(ips)
    summary = {"hosts": len(host_list), "wildcards": 0, "ips": len(ip_list), "skipped_wildcard": 0}

    if mode == "basic":
        return host_list + ip_list, summary

    lines: list[str] = []
    if not ips_only:
        if mode == "advanced-wildcard":
            apexes: set[str] = set()
            fallback: list[str] = []
            for h in host_list:
                apex = registrable(h)
                if not apex:
                    summary["skipped_wildcard"] += 1
                    if verbose:
                        err(f"skip wildcard for {h}: unsafe suffix")
                    fallback.append(h)
                    continue
                apexes.add(apex)
            lines = [rf"^(.*\.)?{re.escape(a)}$" for a in sorted(apexes)]
            lines.extend(host_re(h) for h in sorted(fallback))
            summary["wildcards"] = len(apexes)
            summary["hosts"] = len(fallback)
        else:
            lines = [host_re(h) for h in host_list]

    if not hosts_only:
        lines.extend(host_re(ip) for ip in ip_list)

    return lines, summary


def main() -> int:
    args = parse_args()
    path = out_path(args.output)

    fh = sys.stdin if args.input == "-" else open(args.input, newline="", encoding="utf-8", errors="replace")
    try:
        hosts, ips, st = collect(csv.DictReader(fh), args.skip_cdn, args.verbose)
    finally:
        if args.input != "-":
            fh.close()

    lines, summary = build(args.mode, hosts, ips, args.hosts_only, args.ips_only, args.verbose)
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")

    parts = [
        f"rows={st.get('rows', 0)}",
        f"hosts={summary['hosts']}",
        f"wildcards={summary['wildcards']}",
        f"ips={summary['ips']}",
        f"lines={len(lines)}",
    ]
    for k in ("skipped_cdn", "skipped_service", "skipped_failed", "skipped_bad"):
        if st.get(k):
            parts.append(f"{k}={st[k]}")
    if summary.get("skipped_wildcard"):
        parts.append(f"skipped_wildcard={summary['skipped_wildcard']}")
    parts.append(f"written={path}")
    err(" ".join(parts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
