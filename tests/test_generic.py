import asyncio
from pathlib import Path
import secrets
import socket
import struct
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from wire import Lease, checksum, dhcp_reply, acquire_lease, inbound, lease_from_options
from network import list_namespaces
from dns_proxy import Resolver
from gateway import relay

MAC=b'\x02'+bytes(5)


def options(address='192.0.2.45',gateway='192.0.2.1',dns='192.0.2.99'):
    return {1:socket.inet_aton('255.255.255.0'),3:socket.inet_aton(gateway),6:socket.inet_aton(dns),51:(600).to_bytes(4,'big')}


def reply(xid,kind):
    b=bytearray(240);b[:3]=b'\x02\x01\x06';b[4:8]=xid.to_bytes(4,'big')
    b[16:20]=socket.inet_aton('192.0.2.45');b[28:34]=MAC;b[236:240]=bytes.fromhex('63825363')
    for code,value in {**options(),53:bytes([kind]),54:socket.inet_aton('192.0.2.1')}.items():b+=bytes([code,len(value)])+value
    b+=b'\xff';u=struct.pack('!4H',67,68,len(b)+8,0)+b
    p=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),0,0,64,17,0,bytes(4),b'\xff'*4));struct.pack_into('!H',p,10,checksum(p))
    return b'\xff'*6+MAC+b'\x08\x00'+p+u


class GenericTests(unittest.TestCase):
    def test_dynamic_dhcp_networks(self):
        for address,gateway,dns in [('192.0.2.45','192.0.2.1','192.0.2.99'),('203.0.113.12','203.0.113.7','198.51.100.63')]:
            lease=lease_from_options(address,options(address,gateway,dns))
            self.assertEqual((lease.address,lease.gateway,lease.dns),(address,gateway,(dns,)))
        with self.assertRaises(RuntimeError):lease_from_options('192.0.2.45',{k:v for k,v in options().items() if k!=6})

    def test_dhcp_wrong_xid_and_truncation(self):
        packet=reply(123,2)
        self.assertIsNone(dhcp_reply(packet,MAC,124))
        for length in range(len(packet)):self.assertIsNone(dhcp_reply(packet[:length],MAC,123))

    def test_uninterpreted_frames(self):
        for ethertype in [b'\x08\x00',b'\x08\x06',b'\x86\xdd',b'\x81\x00',b'\x88\xb5']:
            frame=MAC+secrets.token_bytes(6)+ethertype+secrets.token_bytes(500)
            self.assertEqual(inbound(frame,MAC),frame)
            self.assertEqual(inbound(bytes(6)+frame[6:],MAC),frame)
        self.assertIsNone(inbound('text',MAC))

    def test_lan_dns_clients(self):
        r=Resolver('192.168.77.0/24', None)
        self.assertTrue(r.accepts('192.168.77.2'))
        self.assertTrue(r.accepts('192.168.77.3'))
        self.assertFalse(r.accepts('192.168.78.2'))
        self.assertFalse(r.accepts('203.0.113.1'))

    def test_namespace_discovery(self):
        for out in ['', '\n','[]']:
            with patch('network.command',return_value=SimpleNamespace(stdout=out)):self.assertEqual(list_namespaces(),[])
        with patch('network.command',return_value=SimpleNamespace(stdout='not json')):
            with self.assertRaises(RuntimeError):list_namespaces()


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_dhcp_exchange(self):
        class WS:
            def __init__(self):self.queue=asyncio.Queue();self.n=0
            async def send(self,p):
                self.n+=1;xid=int.from_bytes(p[46:50],'big')
                await self.queue.put(reply(xid,2 if self.n==1 else 5))
            async def recv(self):return await self.queue.get()
        self.assertEqual(await acquire_lease(WS(),MAC),Lease('192.0.2.45','192.0.2.1',24,600,('192.0.2.99',)))

    async def test_no_dns_fallback(self):
        r=Resolver('127.0.0.1',lambda _: self.fail('Must not create a host DNS socket'))
        with self.assertRaises(OSError):await r.resolve(struct.pack('!6H',1,0x100,0,0,0,0))
        self.assertEqual(r.counts['errors'],1)

    async def test_websocket_byte_preservation(self):
        from websockets.asyncio.server import serve
        from websockets.asyncio.client import connect
        frame=MAC+MAC+b'\x88\xb5'+secrets.token_bytes(1200)
        observed=asyncio.get_running_loop().create_future()
        async def server(ws):
            await ws.send(frame);observed.set_result(await ws.recv());await ws.wait_closed()
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM);a.setblocking(False);b.setblocking(False)
        stop=asyncio.Event()
        try:
            async with serve(server,'127.0.0.1',0) as svc:
                async with connect(f'ws://127.0.0.1:{svc.sockets[0].getsockname()[1]}',proxy=None) as ws:
                    t=asyncio.create_task(relay(ws,a.fileno(),MAC,Lease('192.0.2.45','192.0.2.1',24,600),stop))
                    loop=asyncio.get_running_loop()
                    self.assertEqual(await asyncio.wait_for(loop.sock_recv(b,2048),1),frame)
                    await loop.sock_sendall(b,frame)
                    self.assertEqual(await asyncio.wait_for(observed,1),frame)
                    stop.set();await asyncio.wait_for(t,1)
        finally:a.close();b.close()
