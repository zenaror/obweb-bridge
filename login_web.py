#!/usr/bin/env python3
"""Prepare an Outbreak Web identity. This is separate from packet forwarding."""
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import urllib.error
import urllib.request

REGISTER_URL = 'https://outbreakweb.com/api/kk/register'
NAME = re.compile(r'[A-Za-z0-9]{1,15}\Z')
TRANSFER = re.compile(r'REO1-([A-Za-z0-9]{1,15})-([0-9a-f]{32})\Z')


def credential(name, token):
    if not NAME.fullmatch(name) or not re.fullmatch(r'[0-9a-f]{32}', token):
        raise ValueError('Invalid identity')
    return hashlib.sha256(f'reo-web:{name}:{token}'.encode()).hexdigest()[:12]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def register(name, secret, opener=None):
    """Never print remote bodies, request bodies, headers or secrets."""
    request = urllib.request.Request(
        REGISTER_URL,
        data=json.dumps({'name': name, 'credential': secret}).encode(),
        headers={'Content-Type': 'application/json', 'Origin': 'https://outbreakweb.com',
                 'Referer': 'https://outbreakweb.com/file1/', 'User-Agent': 'Mozilla/5.0'},
        method='POST')
    opener = opener or urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def state_path():
    base = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))
    return base / 'outbreak-web-login' / 'identities.json'


def load_state(path):
    if not path.exists():
        return {'identities': {}}
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or not isinstance(value.get('identities'), dict):
        raise ValueError('Invalid local state')
    for name, token in value['identities'].items():
        credential(name, token)
    return value


def save_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix='.identity-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    if os.geteuid() == 0:
        raise ValueError('Run the launcher as a regular user, without sudo.')
    # All interactive credentials stay in the local terminal, not shell stdout/logs.
    with open('/dev/tty', 'w') as tty, open('/dev/tty', 'r') as tty_input:
        def say(text):
            tty.write(text + '\n'); tty.flush()
        def ask(text):
            tty.write(text); tty.flush()
            answer = tty_input.readline()
            if not answer:
                raise EOFError()
            return answer.strip()
        path = state_path()
        state = load_state(path)
        say('Outbreak Web login — account setup, separate from the WSS tunnel.')
        while True:
            previous = state.get('last_name', '')
            name = ask(f'Username [{previous}]: ' if previous else 'Username: ') or previous
            if not NAME.fullmatch(name):
                say('Use 1 to 15 letters and numbers, with no spaces.'); continue
            token = state['identities'].get(name)
            if token is None:
                say('If this is already your username on the site, import the transfer code from the page.')
                mode = ask('[N] New username / [I] Import code / [B] Back: ').lower()
                if mode == 'b':
                    continue
                if mode == 'i':
                    transfer = getpass.getpass('REO1 code (hidden input): ', stream=tty).strip()
                    match = TRANSFER.fullmatch(transfer)
                    if not match or match[1] != name:
                        say('Invalid code or the code belongs to a different username.'); continue
                    token = match[2]
                elif mode == 'n':
                    token = secrets.token_hex(16)
                else:
                    continue
                # Persist BEFORE the request: a timeout must not lose the identity.
                state['identities'][name] = token
                save_state(path, state)
            secret = credential(name, token)
            say('Registering/checking the username with Outbreak Web…')
            status = register(name, secret)
            if status == 409:
                say('Username already registered with a different credential. Choose another username or import your code.')
                # Keep the pending identity on disk; explicit import may replace it.
                if ask('Import your code for this username? [y/N]: ').lower() == 'y':
                    transfer = getpass.getpass('REO1 code (hidden input): ', stream=tty).strip()
                    match = TRANSFER.fullmatch(transfer)
                    if match and match[1] == name:
                        state['identities'][name] = match[2]
                        save_state(path, state)
                continue
            if not 200 <= status < 300:
                raise ValueError(f'The service rejected registration (HTTP {status}); the gateway was not started.')
            state['last_name'] = name
            save_state(path, state)
            say('Account accepted. Enter these details on the game login screen:')
            say(f'  Username: {name}')
            say(f'  Password: {secret}')
            say('This is the game password. Keep it private; do not share screenshots of this screen.')
            say('It is not entered automatically in ARMSX2. Use the ISO with the DNAS bypass.')
            ask('Save these details, then press Enter to start the gateway:')
            return


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nLogin cancelled; the gateway was not started.')
        raise SystemExit(1)
    except (OSError, ValueError, urllib.error.URLError) as error:
        # Exception messages from network libraries may contain URLs/data; only
        # locally constructed validation messages are safe to display.
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print(f'Login setup failed: {detail}')
        raise SystemExit(1)
