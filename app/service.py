"""Keep a service available across transport loss, without a session deadline."""
import asyncio


class Reconnect(Exception):
    """A transport session ended; retain local resources and try a new session."""


SAFE_REASONS = {
    'Remote gateway ARP did not respond', 'Remote DHCP lease expired',
    'Remote DHCP rejected renewal', 'Remote DHCP configuration changed',
    'Remote network setup unavailable', 'WebSocket closed by the server',
    'WSS transport interrupted', 'Invalid Ethernet frame from WSS',
    'Remote DHCP unavailable', 'Remote DHCP changed the tunnel network',
    'Remote DHCP network conflicts with local routing',
}


def reconnect_details(error):
    """Only local reason labels and numeric codes; never remote exception text."""
    reason = str(error)
    details = [reason if reason in SAFE_REASONS else 'Transport session interrupted']
    cause = error.__cause__
    if isinstance(cause, TimeoutError):
        details.append('timeout')
    elif isinstance(cause, OSError):
        details.append('OS/network error')
        if type(cause.errno) is int:
            details.append(f'errno={cause.errno}')
    if cause is not None:
        from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus
        if isinstance(cause, InvalidStatus):
            status = getattr(cause.response, 'status_code', None)
            if type(status) is int:
                details.append(f'WebSocket handshake rejected; HTTP status={status}')
        elif isinstance(cause, InvalidHandshake):
            details.append('WebSocket handshake failed')
        if isinstance(cause, ConnectionClosed):
            details.append('WebSocket connection closed')
            for label, close in (('received', cause.rcvd), ('sent', cause.sent)):
                if close is not None and isinstance(close.code, int):
                    details.append(f'close_{label}={close.code}')
            if cause.rcvd is None:
                details.append('no close frame received')
    return '; '.join(details)


async def serve(session, log, *, pause=asyncio.sleep):
    delay = 1
    while True:
        started = asyncio.get_running_loop().time()
        try:
            await session()
        except Reconnect as error:
            if asyncio.get_running_loop().time() - started >= 30:
                delay = 1
            elapsed = asyncio.get_running_loop().time() - started
            log(f'Tunnel offline; reconnecting in {delay}s. The application remains available. '
                f'Reason: {reconnect_details(error)}; session duration={elapsed:.1f}s.')
            await pause(delay)
            delay = min(delay * 2, 30)
        else:
            return
