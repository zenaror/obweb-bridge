import sys
from pathlib import Path
import unittest
from unittest.mock import patch, AsyncMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from diagnostico import probe_remote_dns

class DiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_reply_is_transport_success_even_nxdomain(self):
        response=b'\0\1\x81\x83'+bytes(8)
        with patch('diagnostico.Resolver.resolve',new_callable=AsyncMock,return_value=response) as resolve:
            result=await probe_remote_dns('192.0.2.53','endpoint.invalid')
            self.assertEqual(result,{'response_received':True,'rcode':3})
            self.assertIn(b'endpoint',resolve.call_args.args[0])
    async def test_dns_error_is_bounded_summary(self):
        with patch('diagnostico.Resolver.resolve',new_callable=AsyncMock,side_effect=OSError('private diagnostic detail')):
            result=await probe_remote_dns('192.0.2.53','endpoint.invalid')
            self.assertEqual(result,{'response_received':False,'error_type':'OSError'})

class DNSMetadataTests(unittest.TestCase):
    def test_target_match_without_disclosing_other_names(self):
        import struct
        from diagnostico import dns_metadata
        q=struct.pack('!6H',9,0x100,1,0,0,0)+b'\x07example\x07invalid\0\0\1\0\1'
        match=dns_metadata(q,'EXAMPLE.INVALID')
        self.assertTrue(match['dns_matches_requested_name'])
        self.assertEqual((match['dns_qtype'],match['dns_qclass']),(1,1))
        other=dns_metadata(q,'different.invalid')
        self.assertFalse(other['dns_matches_requested_name'])
        self.assertNotIn('example',repr(other))
    def test_malformed_question_is_bounded(self):
        import struct
        from diagnostico import dns_metadata
        data=struct.pack('!6H',9,0x100,1,0,0,0)+b'\xc0\x0c'
        self.assertNotIn('dns_qtype',dns_metadata(data,'example.invalid'))
