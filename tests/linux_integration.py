"""Isolated regression: arbitrary traffic/DNS must reach the tunnel, never the home router."""
import asyncio,ctypes,fcntl,json,os,secrets,socket,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from network import Network,inventory,command,list_namespaces,namespace_socket,STATE,NS,VETH
from wire import Lease
from gateway import relay
from dns_proxy import Resolver,DNSDatagrams
from diagnostico import probe_remote_dns


def ip(*args):return command(['ip',*args])
def inside(ns,*args):return ip('netns','exec',ns,*args)


def tap(ns):
    current=os.open('/proc/self/ns/net',os.O_RDONLY);target=os.open('/run/netns/'+ns,os.O_RDONLY)
    libc=ctypes.CDLL(None,use_errno=True)
    try:
        assert libc.setns(target,0)==0
        fd=os.open('/dev/net/tun',os.O_RDWR|os.O_NONBLOCK)
        fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',b'remote-tap',0x1002))
    finally:
        assert libc.setns(current,0)==0
        os.close(current);os.close(target)
    return fd


SERVER=r'''
import asyncio,json,socket,struct,sys
c=json.loads(sys.argv[1])
async def tcp(r,w):
 data=await r.read(2048);w.write(b'WSS:'+data);await w.drain();w.close();await w.wait_closed()
class UDP(asyncio.DatagramProtocol):
 def connection_made(self,t):self.t=t
 def datagram_received(self,b,a):self.t.sendto(b'WSS:'+b,a)
def dns(b):return b[:2]+b'\x81\x80'+b[4:6]+b'\x00\x01\x00\x00\x00\x00'+b[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,23,4)+socket.inet_aton('198.51.100.79')
class DNS(asyncio.DatagramProtocol):
 def connection_made(self,t):self.t=t
 def datagram_received(self,b,a):self.t.sendto(dns(b),a)
async def dns_tcp(r,w):
 n=int.from_bytes(await r.readexactly(2),'big');b=await r.readexactly(n);b=dns(b)
 w.write(len(b).to_bytes(2,'big')+b);await w.drain();w.close();await w.wait_closed()
async def main():
 servers=[await asyncio.start_server(tcp,c['dest'],c['tcp']),await asyncio.start_server(dns_tcp,c['dns'],53)]
 await asyncio.get_running_loop().create_datagram_endpoint(UDP,local_addr=(c['dest'],c['udp']))
 await asyncio.get_running_loop().create_datagram_endpoint(DNS,local_addr=(c['dns'],53))
 print('READY',flush=True);await asyncio.Event().wait()
asyncio.run(main())
'''
ROUTER=r'''
import socket,sys
s=socket.socket();s.bind(('203.0.113.77',int(sys.argv[1])));s.listen();print('READY',flush=True)
while True:
 c,a=s.accept();c.sendall(b'HOME');c.close();print(a[0],flush=True)
'''
CLIENT=r'''
import socket,json,struct,sys
c=json.loads(sys.argv[1])
with socket.create_connection((c['dest'],c['tcp']),timeout=4) as s:
 s.sendall(b'arbitrary TCP');assert s.recv(2048)==b'WSS:arbitrary TCP'
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(4);s.sendto(b'arbitrary UDP',(c['dest'],c['udp']));assert s.recv(2048)==b'WSS:arbitrary UDP'
payload=struct.pack('!BBHHH',8,0,0,1,1)+b'generic-icmp'
words=struct.unpack('!'+'H'*(len(payload)//2),payload);total=sum(words)
while total>>16:total=(total&65535)+(total>>16)
payload=payload[:2]+((~total)&65535).to_bytes(2,'big')+payload[4:]
with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP) as sock:
 sock.settimeout(4);sock.sendto(payload,(c['dest'],0));response=sock.recv(2048);assert response[(response[0]&15)*4]==0 and response.endswith(b'generic-icmp')
q=struct.pack('!6H',123,0x100,1,0,0,0)+b'\x0arandomname\x07invalid\0\0\1\0\1'
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(4);s.sendto(q,('192.168.77.1',53));b=s.recv(2048);assert b[-4:]==socket.inet_aton('198.51.100.79')
with socket.create_connection(('192.168.77.1',53),timeout=4) as s:
 s.sendall(len(q).to_bytes(2,'big')+q);n=int.from_bytes(s.recv(2),'big');b=s.recv(n);assert b[-4:]==socket.inet_aton('198.51.100.79')
print('Arbitrary TCP/UDP/ICMP and arbitrary-domain DNS UDP/TCP reached WSS')
'''


async def proc(ns,code,*args):
    return await asyncio.create_subprocess_exec('ip','netns','exec',ns,sys.executable,'-u','-c',code,*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)


async def main():
    assert os.environ.get('OBW_PRIVATE_TEST')=='1','Use linux_integration.sh'
    assert list_namespaces()==[]
    ip('link','set','lo','up');ip('link','add','testlan','type','bridge')
    ip('address','add','192.168.77.1/24','dev','testlan');ip('link','set','testlan','up')
    for ns,addr in [('android-test','192.168.77.2'),('router-test','192.168.77.254')]:
        ip('netns','add',ns);a=ns.split('-')[0]
        ip('link','add',a+'-h','type','veth','peer','name',a+'-p')
        ip('link','set',a+'-p','netns',ns);ip('link','set',a+'-h','master','testlan');ip('link','set',a+'-h','up')
        inside(ns,'ip','address','add',addr+'/24','dev',a+'-p');inside(ns,'ip','link','set',a+'-p','up');inside(ns,'ip','link','set','lo','up')
    inside('android-test','ip','route','add','default','via','192.168.77.1')
    ip('route','add','default','via','192.168.77.254','dev','testlan')
    c=inventory('testlan')
    cfg={'dest':'203.0.113.77','tcp':secrets.randbelow(20000)+20000,'udp':secrets.randbelow(20000)+40000,'dns':'192.0.2.53'}
    inside('router-test','ip','address','add',cfg['dest']+'/32','dev','lo')
    router=await proc('router-test',ROUTER,str(cfg['tcp']));assert await router.stdout.readline()==b'READY\n'
    ip('netns','add','remote-test');remote_fd=tap('remote-test')
    inside('remote-test','ip','address','add','192.0.2.1/24','dev','remote-tap');inside('remote-test','ip','link','set','remote-tap','up');inside('remote-test','ip','link','set','lo','up')
    for addr in [cfg['dest'],cfg['dns']]:inside('remote-test','ip','address','add',addr+'/32','dev','lo')
    remote=await proc('remote-test',SERVER,json.dumps(cfg));assert await remote.stdout.readline()==b'READY\n'
    keys=['net.ipv4.ip_forward','net.ipv4.conf.testlan.forwarding','net.ipv4.conf.all.rp_filter','net.ipv4.conf.all.send_redirects','net.ipv4.conf.testlan.send_redirects']
    before={k:command(['sysctl','-n',k]).stdout for k in keys}
    old_rules=ip('-j','rule','show').stdout
    n=Network(c);mac=b'\x02'+secrets.token_bytes(5);queue=asyncio.Queue();loop=asyncio.get_running_loop();stop=asyncio.Event()
    def rx():
        try:queue.put_nowait(os.read(remote_fd,65535))
        except BlockingIOError:pass
    class WSS:
        async def send(self,data):os.write(remote_fd,data)
        def __aiter__(self):return self
        async def __anext__(self):return await queue.get()
    task=None;dns_udp=None;dns_tcp=None
    try:
        n.setup(mac);lease=Lease('192.0.2.45','192.0.2.1',24,600,(cfg['dns'],));n.activate(lease)
        r=Resolver(c['client_network'],namespace_socket);r.servers=lease.dns
        dns_udp,_=await loop.create_datagram_endpoint(lambda:DNSDatagrams(r),local_addr=('192.168.77.1',53))
        dns_tcp=await asyncio.start_server(r.tcp,'192.168.77.1',53)
        loop.add_reader(remote_fd,rx);task=asyncio.create_task(relay(WSS(),n.fd,mac,lease,stop,r))
        assert await probe_remote_dns(cfg['dns'], 'transport-check.invalid') == {'response_received':True, 'rcode':0}
        client=await proc('android-test',CLIENT,json.dumps(cfg));out,err=await asyncio.wait_for(client.communicate(),20)
        assert client.returncode==0,err.decode();print(out.decode().strip());assert r.counts['answers']==2
        inside('android-test','ip','address','delete','192.168.77.2/24','dev','android-p')
        inside('android-test','ip','address','add','192.168.77.3/24','dev','android-p')
        inside('android-test','ip','route','replace','default','via','192.168.77.1')
        client=await proc('android-test',CLIENT,json.dumps(cfg));out,err=await asyncio.wait_for(client.communicate(),20)
        assert client.returncode==0,err.decode();assert r.counts['answers']==4
        print('Changed client IPv4 without restarting bridge: TCP/UDP/ICMP/DNS passed')
        # Host traffic must still follow its own home router, unaffected by client-only policy.
        reader,writer=await asyncio.open_connection(cfg['dest'],cfg['tcp']);assert await reader.read(20)==b'HOME';writer.close();await writer.wait_closed()
        assert await asyncio.wait_for(router.stdout.readline(),1)==b'192.168.77.1\n'
        ip('link','set',VETH,'down')
        failure="import socket,sys; s=socket.socket(); s.settimeout(1); code=s.connect_ex(('203.0.113.77',int(sys.argv[1]))); s.close(); assert code != 0; print('No home-router fallback with link down')"
        client=await proc('android-test',failure,str(cfg['tcp']));out,err=await asyncio.wait_for(client.communicate(),3);assert client.returncode==0,err.decode();print(out.decode().strip())
        try:
            leak=await asyncio.wait_for(router.stdout.readline(),.15)
            raise AssertionError('Unexpected home-router traffic: '+repr(leak))
        except asyncio.TimeoutError:pass
        stop.set();await asyncio.wait_for(task,2)
    finally:
        if task:task.cancel();await asyncio.gather(task,return_exceptions=True)
        if dns_udp:dns_udp.close()
        if dns_tcp:dns_tcp.close();await dns_tcp.wait_closed()
        loop.remove_reader(remote_fd);os.close(remote_fd)
        remote.terminate();router.terminate();await remote.wait();await router.wait()
        n.close()
    assert {k:command(['sysctl','-n',k]).stdout for k in keys}==before
    assert ip('-j','rule','show').stdout==old_rules
    assert not STATE.exists() and NS not in [x['name'] for x in list_namespaces()]
    print('Host routing preserved; policy/namespace/firewall/sysctls cleaned up')


asyncio.run(main())
