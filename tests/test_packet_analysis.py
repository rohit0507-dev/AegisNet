"""Offline Scapy fixtures: no sockets, scans, or transmitted traffic."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scapy.config import conf
from scapy.interfaces import NetworkInterfaceDict

# Only these tests disable interface discovery for offline packet construction.
conf.route_autoload=False
conf.route6_autoload=False
with patch.object(NetworkInterfaceDict,'reload'):
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
    from scapy.layers.inet6 import ICMPv6EchoRequest
    from app.analysis.flow_engine import FlowEngine
    from app.capture.packet_capture import PacketCapture
from app.detection.rule_engine import RuleEngine
from app.detection.port_scan_detector import PortScanDetector
from app.database.database import Database


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.eth=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
        self.ip=IP(src='192.0.2.1',dst='192.0.2.2')
        self.v6=IPv6(src='2001:db8::1',dst='2001:db8::2')

    def test_protocols_and_dns_decoding(self):
        fixtures=[(self.ip/TCP(),'TCP',4),(self.v6/UDP(),'UDP',6),
            (self.ip/ICMP(),'ICMP',4),(self.v6/ICMPv6EchoRequest(),'ICMPv6',6),
            (ARP(hwsrc=self.eth.src,hwdst=self.eth.dst,psrc='192.0.2.1',pdst='192.0.2.2'),'ARP',None)]
        for payload,protocol,version in fixtures:
            engine=FlowEngine();engine.process_packet(self.eth/payload)
            f=engine.get_all_features()[0]
            self.assertEqual((f['protocol'],f['ip_version']),(protocol,version))
        engine=FlowEngine();engine.process_packet(self.eth/self.ip/UDP(dport=53)/DNS(qd=DNSQR(qname='example.test')))
        self.assertEqual(engine.get_all_features()[0]['application_protocol'],'DNS')

    def test_timestamps_flags_and_directional_flow(self):
        engine=FlowEngine()
        a=self.eth/self.ip/TCP(sport=1234,dport=443,flags='S');a.time=1000
        b=self.eth/self.ip/TCP(sport=1234,dport=443,flags='A');b.time=1002
        engine.process_packet(a);engine.process_packet(b)
        f=engine.get_all_features()[0]
        self.assertEqual(f['duration'],2);self.assertEqual(f['packet_count'],2)
        self.assertEqual(f['total_bytes'],len(a)+len(b));self.assertEqual(f['syn_count'],1)
        self.assertEqual(f['ack_count'],1);self.assertEqual(f['packets_per_second'],1)
        engine.process_packet(self.eth/IP(src='192.0.2.2',dst='192.0.2.1')/TCP(sport=443,dport=1234))
        self.assertEqual(len(engine.get_all_features()),2)

    def test_syn_and_icmp_thresholds(self):
        for proto,number,expected in [(TCP(flags='S'),100,'SYN_FLOOD'),(ICMP(),200,'ICMP_FLOOD')]:
            engine=FlowEngine()
            for i in range(number):
                p=self.eth/self.ip/proto;p.time=1000+i*.005;engine.process_packet(p)
            self.assertIn(expected,{x['type'] for x in RuleEngine().detect(next(iter(engine.flows.values())))})
        engine=FlowEngine();engine.process_packet(self.eth/self.ip/ICMP())
        self.assertNotIn('ICMP_FLOOD',{x['type'] for x in RuleEngine().detect(next(iter(engine.flows.values())))})

    def test_port_scan_threshold(self):
        flows=[dict(source_ip='192.0.2.1',destination_ip='192.0.2.2',destination_port=p) for p in range(1,21)]
        self.assertEqual(len(PortScanDetector().detect(flows)),1)
        self.assertEqual(PortScanDetector().detect(flows[:19]),[])

    def test_complete_window_persists_protocol_and_ml_evidence(self):
        class Interface:name='offline-fixture'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'window.db'
            with patch('app.capture.packet_capture.Database',side_effect=lambda:Database(path)),patch.object(conf.ifaces,'dev_from_name',return_value=Interface()):
                output=io.StringIO()
                with contextlib.redirect_stdout(output):
                    capture=PacketCapture(interface='offline-fixture')
                    for i in range(3):
                        p=self.eth/self.ip/TCP(sport=12000,dport=443,flags='A')/Raw(b'x'*64)
                        p.time=1000+i*.5;capture.process_packet(p)
                    capture.process_window()
                self.assertNotIn('ERROR]',output.getvalue())
                row=capture.database.connection.execute('SELECT packet_count,ip_version,ml_available FROM flow_records').fetchone()
                self.assertEqual(row,(3,4,1))
                self.assertEqual(capture.database.connection.execute('SELECT COUNT(*) FROM response_events').fetchone()[0],1)
                self.assertEqual(capture.flow_engine.get_all_features(),[])
                capture.database.connection.close()


if __name__=='__main__':unittest.main()
