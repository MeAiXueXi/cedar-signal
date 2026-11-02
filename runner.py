"""Measure GET request throughput for a local domain-URL template library."""

import argparse
import asyncio
from collections import Counter
import csv
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import sqlite3
import time
from urllib.parse import urlsplit, urlunsplit

import aiohttp

ROOT = Path(__file__).resolve().parent
MARKER = '{{DOMAIN}}'


def choose_proxy(explicit, environ, direct=False):
    if direct:
        return None
    proxy = explicit
    if not proxy:
        proxy = next((environ.get(key) for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy')
                      if environ.get(key)), None)
    if not proxy:
        return None
    parts = urlsplit(proxy)
    if (parts.scheme not in ('http', 'https') or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.path not in ('', '/') or parts.query or parts.fragment
            or any(char.isspace() for char in proxy)):
        raise ValueError('Use an HTTP(S) proxy URL without credentials; prefer HTTP_PROXY over a SOCKS-only ALL_PROXY')
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError('Invalid proxy port')
    return proxy


def public_ip(value):
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast


def validate_url(url):
    parts = urlsplit(url)
    if (parts.scheme not in ('http', 'https') or not parts.hostname
            or parts.username is not None or parts.password is not None
            or any(char.isspace() for char in url) or MARKER in url):
        raise ValueError('Invalid HTTP(S) target URL')
    if parts.port not in (None, 80, 443):
        raise ValueError('Nonstandard target port')
    host = parts.hostname.lower()
    if '.' not in host or host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')):
        raise ValueError('Local target hostname')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not public_ip(host):
        raise ValueError('Nonpublic target IP')
    return urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))


def prepare_urls(path, domain, sample, seed):
    if not domain or any(char in domain for char in '/:@?#{}') or any(char.isspace() for char in domain):
        raise ValueError('Use a bare target hostname')
    validate_url('https://' + domain)
    urls = []
    seen = set()
    rejected = 0
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if MARKER not in line:
                raise ValueError('Missing target marker')
            url = validate_url(line.replace(MARKER, domain))
        except ValueError:
            rejected += 1
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    total = len(urls)
    if sample and total > sample:
        urls = random.Random(seed).sample(urls, sample)
    return urls, total, rejected


class PublicResolver(aiohttp.abc.AbstractResolver):
    def __init__(self):
        self.resolver = aiohttp.resolver.ThreadedResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        records = await self.resolver.resolve(host, port, family)
        if not records or any(not public_ip(record['host']) for record in records):
            raise OSError('Nonpublic DNS address rejected')
        return records

    async def close(self):
        await self.resolver.close()


def percentile(values, ratio):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * ratio))] if values else 0


async def run(args):
    urls, total, rejected = prepare_urls(args.input, args.domain, args.sample, args.seed)
    if not urls:
        raise ValueError('No accepted URLs')
    args.output.mkdir(parents=True, exist_ok=False)
    db = sqlite3.connect(args.output / 'requests.sqlite')
    db.execute('CREATE TABLE requests (url TEXT PRIMARY KEY,status INTEGER,outcome TEXT,seconds REAL,location TEXT,error TEXT)')
    queue = asyncio.Queue()
    for url in urls:
        queue.put_nowait(url)
    outcomes = Counter()
    statuses = Counter()
    timings = []
    completed = 0
    started = time.monotonic()
    print('PROBE_START urls=' + str(len(urls)) + ' concurrency=' + str(args.concurrency)
          + ' timeout=' + str(args.timeout) + ' redirects=not_followed proxy=' + (args.proxy or 'none'), flush=True)

    async def consume(session):
        nonlocal completed
        while True:
            if time.monotonic() - started >= args.max_seconds:
                return
            try:
                url = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            begin = time.monotonic()
            status = None
            outcome = 'error'
            location = ''
            error = ''
            try:
                async with session.get(url, allow_redirects=False, proxy=args.proxy) as response:
                    status = response.status
                    location = response.headers.get('Location', '')
                    outcome = 'http_' + str(status // 100) + 'xx'
                    await response.content.read(1024)
            except (asyncio.TimeoutError, TimeoutError):
                outcome = 'timeout'
            except aiohttp.ClientError as exc:
                outcome = type(exc).__name__
                error = ascii(str(exc))[:600]
            elapsed = time.monotonic() - begin
            timings.append(elapsed)
            outcomes[outcome] += 1
            if status is not None:
                statuses[str(status)] += 1
            db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)', (url, status, outcome, elapsed, location, error))
            completed += 1
            if completed % 100 == 0 or completed == len(urls):
                db.commit()
                print('PROBE_PROGRESS completed=' + str(completed) + '/' + str(len(urls))
                      + ' elapsed_seconds=' + str(round(time.monotonic() - started, 1)), flush=True)
            queue.task_done()

    resolver = aiohttp.resolver.ThreadedResolver() if args.proxy else PublicResolver()
    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=1, resolver=resolver)
    try:
        async with aiohttp.ClientSession(
                connector=connector, trust_env=False,
                timeout=aiohttp.ClientTimeout(total=args.timeout),
                headers={'User-Agent': 'BacklinkProbe/1.0', 'Range': 'bytes=0-1023'}) as session:
            await asyncio.gather(*(consume(session) for _ in range(args.concurrency)))
    finally:
        await resolver.close()
        db.commit()
    elapsed = time.monotonic() - started
    done = len(timings)
    summary = {
        'domain': args.domain, 'input': str(args.input), 'library_urls': total,
        'rejected_templates': rejected, 'sample': len(urls), 'seed': args.seed,
        'concurrency': args.concurrency, 'timeout_seconds': args.timeout,
        'completed': done, 'remaining': len(urls) - done, 'complete': done == len(urls),
        'redirects_followed': False, 'proxy': args.proxy,
        'target_dns': 'proxy' if args.proxy else 'local_public_only',
        'elapsed_seconds': round(elapsed, 3),
        'requests_per_second': round(done / elapsed, 3),
        'mean_request_seconds': round(sum(timings) / done, 3) if done else 0,
        'p50_seconds': round(percentile(timings, .5), 3),
        'p95_seconds': round(percentile(timings, .95), 3),
        'estimated_full_hours': round(total * elapsed / done / 3600, 3) if done else None,
        'outcomes': dict(outcomes), 'statuses': dict(statuses),
    }
    with (args.output / 'summary.txt').open('w', encoding='utf-8', newline='\n') as stream:
        for key, value in summary.items():
            stream.write(key + '=' + json.dumps(value, ensure_ascii=True) + '\n')
    with (args.output / 'requests.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(('url', 'status', 'outcome', 'seconds', 'location', 'error'))
        writer.writerows(db.execute('SELECT * FROM requests ORDER BY rowid'))
    db.close()
    print('PROBE_COMPLETE ' + json.dumps(summary, ensure_ascii=True), flush=True)
    return done == len(urls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'data/urls.txt')
    parser.add_argument('--domain', default=os.environ.get('TARGET_DOMAIN'))
    parser.add_argument('--sample', type=int, default=1000, help='Use zero for the complete library')
    parser.add_argument('--seed', type=int, default=20261102)
    parser.add_argument('--concurrency', type=int, default=20)
    parser.add_argument('--timeout', type=float, default=8)
    parser.add_argument('--max-seconds', type=float, default=18000)
    parser.add_argument('--proxy', help='HTTP(S) proxy; otherwise use HTTPS_PROXY, HTTP_PROXY or ALL_PROXY')
    parser.add_argument('--direct', action='store_true', help='Ignore all proxy environment variables')
    parser.add_argument('--output', type=Path, default=ROOT / 'runs' / datetime.now().strftime('%Y%m%d-%H%M%S'))
    args = parser.parse_args()
    if args.sample < 0 or not 1 <= args.concurrency <= 100 or not 1 <= args.timeout <= 60:
        parser.error('Use a nonnegative sample, concurrency 1..100 and timeout 1..60')
    if not 1 <= args.max_seconds <= 18000:
        parser.error('Use max-seconds 1..18000')
    try:
        args.proxy = choose_proxy(args.proxy, os.environ, args.direct)
    except ValueError as error:
        parser.error(str(error))
    if not args.domain:
        parser.error('Configure TARGET_DOMAIN or supply --domain')
    if not asyncio.run(run(args)):
        raise SystemExit('Run incomplete: time budget reached; see saved results')


if __name__ == '__main__':
    main()
