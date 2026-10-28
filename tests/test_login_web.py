import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location('login_web', Path(__file__).resolve().parents[1] / 'login_web.py')
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)


class LoginTests(unittest.TestCase):
    def test_credential_matches_page_algorithm_and_rejects_bad_input(self):
        # Independent public formula; synthetic identity only.
        expected = hashlib.sha256(b'reo-web:BridgeTest:0123456789abcdef0123456789abcdef').hexdigest()[:12]
        self.assertEqual(login.credential('BridgeTest', '0123456789abcdef0123456789abcdef'), expected)
        for name in ('', '../user', 'a' * 16, 'name with spaces'):
            with self.assertRaises(ValueError):
                login.credential(name, '0' * 32)

    def test_registration_wire_contract(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Opener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return Response()
        opener = Opener()
        self.assertEqual(login.register('BridgeTest', '012345abcdef', opener), 200)
        self.assertEqual(opener.request.full_url, 'https://outbreakweb.com/api/kk/register')
        self.assertEqual(opener.request.method, 'POST')
        self.assertEqual(json.loads(opener.request.data), {'name': 'BridgeTest', 'credential': '012345abcdef'})
        self.assertEqual(opener.timeout, 20)

    def test_conflict_does_not_expose_response_body(self):
        class Opener:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, 409, 'Conflict', {}, io.BytesIO(b'PRIVATE BODY'))
        self.assertEqual(login.register('BridgeTest', '012345abcdef', Opener()), 409)

    def test_no_credential_redirect(self):
        self.assertIsNone(login.NoRedirect().redirect_request(None, None, 307, '', {}, 'https://elsewhere.invalid'))

    def test_interactive_create_and_reuse_without_network(self):
        class Terminal(io.StringIO):
            def __exit__(self, *args): pass
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identities.json'
            pairs = []
            for answers in ('BridgeTest\nn\n\n', '\n\n'):
                terminal_in, terminal_out = Terminal(answers), Terminal()
                def open_terminal(name, mode):
                    self.assertEqual(name, '/dev/tty')
                    return terminal_in if mode == 'r' else terminal_out
                def register_pair(name, secret):
                    # Identity exists even before a potentially ambiguous request.
                    self.assertIn(name, login.load_state(path)['identities'])
                    pairs.append((name, secret))
                    return 200
                with patch('builtins.open', side_effect=open_terminal), \
                     patch.object(login, 'state_path', return_value=path), \
                     patch.object(login, 'register', side_effect=register_pair), \
                     patch.object(login.os, 'geteuid', return_value=1000):
                    login.main()
                self.assertIn('Senha:', terminal_out.getvalue())
            self.assertEqual(pairs[0], pairs[1])

    def test_private_persistent_state_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private' / 'identities.json'
            state = {'identities': {'BridgeTest': '0' * 32}}
            login.save_state(path, state)
            self.assertEqual(login.load_state(path), state)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            state['last_name'] = 'BridgeTest'
            login.save_state(path, state)
            self.assertEqual(login.load_state(path), state)
            self.assertEqual(list(path.parent.iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
