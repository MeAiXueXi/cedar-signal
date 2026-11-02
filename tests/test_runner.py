"""Offline target validation and sampling checks for the request probe."""

from pathlib import Path
from contextlib import closing
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import sqlite3

try:
    import aiohttp
except ImportError:
    raise unittest.SkipTest('Install requirements.txt to run optional probe tests')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runner import PublicResolver, choose_proxy, prepare_urls, public_ip, validate_url
import runner


class ProbeTests(unittest.TestCase):
    def test_http_proxy_takes_precedence_over_socks(self):
        env = {'HTTPS_PROXY': 'http://127.0.0.1:10808', 'ALL_PROXY': 'socks5://127.0.0.1:10808'}
        self.assertEqual(choose_proxy(None, env), env['HTTPS_PROXY'])
        self.assertIsNone(choose_proxy(None, env, direct=True))
        self.assertEqual(choose_proxy('http://127.0.0.1:9999', env), 'http://127.0.0.1:9999')
        self.assertEqual(choose_proxy(None, {'http_proxy': env['HTTPS_PROXY']}), env['HTTPS_PROXY'])
        with self.assertRaises(ValueError):
            choose_proxy(None, {'ALL_PROXY': env['ALL_PROXY']})

    def test_reject_nonpublic_and_credential_targets(self):
        for url in ('http://127.0.0.1/', 'http://169.254.169.254/', 'http://localhost/',
                    'https://a.internal/', 'https://user@example.com/',
                    'file:///tmp/a', 'https://example.com:1234/', 'http://[::1]/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)
        self.assertFalse(public_ip('224.0.0.1'))

    def test_fragments_are_not_requested(self):
        self.assertEqual(validate_url('https://example.com/a?q=x#part'), 'https://example.com/a?q=x')

    def test_sample_is_reproducible_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'templates.txt'
            rows = ['https://example.com/' + str(i) + '?d={{DOMAIN}}' for i in range(20)]
            path.write_text('\n'.join(rows + rows + ['http://127.0.0.1/?d={{DOMAIN}}']), encoding='utf-8')
            a = prepare_urls(path, 'target.example', 5, 123)
            self.assertEqual(a, prepare_urls(path, 'target.example', 5, 123))
            self.assertEqual((len(a[0]), a[1], a[2]), (5, 20, 1))
            self.assertTrue(all('target.example' in url for url in a[0]))


class ResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_reject_mixed_public_private_dns(self):
        resolver = PublicResolver()
        resolver.resolver.resolve = AsyncMock(return_value=[{'host': '8.8.8.8'}, {'host': '10.0.0.1'}])
        with self.assertRaises(OSError):
            await resolver.resolve('example.com')
        await resolver.close()


class RunTests(unittest.IsolatedAsyncioTestCase):
    async def test_time_budget_preserves_partial_sql_results(self):
        response = SimpleNamespace(status=200, headers={}, content=SimpleNamespace(read=AsyncMock(return_value=b'ok')))
        response_context = AsyncMock()
        response_context.__aenter__.return_value = response
        session = Mock()
        session.get.return_value = response_context
        session_context = AsyncMock()
        session_context.__aenter__.return_value = session
        resolver = SimpleNamespace(close=AsyncMock())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'input.txt'
            source.write_text('https://example.com/a?d={{DOMAIN}}\nhttps://example.com/b?d={{DOMAIN}}\n', encoding='utf-8')
            args = SimpleNamespace(input=source, domain='target.example', sample=0, seed=1,
                                   output=root / 'output', concurrency=1, timeout=6,
                                   max_seconds=1, proxy=None)
            clock = SimpleNamespace(monotonic=Mock(side_effect=[0, .01, .02, .03, 2, 2.1]))
            with patch.object(runner, 'time', clock), patch.object(runner, 'PublicResolver', return_value=resolver), \
                    patch.object(runner.aiohttp, 'TCPConnector'), \
                    patch.object(runner.aiohttp, 'ClientSession', return_value=session_context):
                self.assertFalse(await runner.run(args))
            with closing(sqlite3.connect(args.output / 'requests.sqlite')) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM requests').fetchone()[0], 1)
            summary = (args.output / 'summary.txt').read_text(encoding='utf-8')
            self.assertIn('completed=1\n', summary)
            self.assertIn('remaining=1\n', summary)
            self.assertIn('complete=false\n', summary)
            self.assertTrue((args.output / 'requests.csv').is_file())


if __name__ == '__main__':
    unittest.main()
