"""API regression checks use temporary data and never capture network traffic."""
import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.dashboard import dashboard
from app.database.database import Database


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'test.db'
        self.db_patch=patch.object(dashboard,'DATABASE_PATH',str(self.path))
        self.db_patch.start();dashboard.initialize_database()
        self.client=dashboard.app.test_client()

    def tearDown(self):
        self.db_patch.stop();self.temp.cleanup()

    def add(self,protocol='TCP',packets=10,size=1000,stamp='2026-01-02T12:00:00',alerts=None,ml=False,source='192.0.2.1'):
        db=Database(self.path)
        features=dict(source_ip=source,destination_ip='192.0.2.2',source_port=12345,
            destination_port=443,protocol=protocol,packet_count=packets,total_bytes=size,duration=1,ml_available=1)
        db.insert_flow(features,{'score':20,'severity':'LOW'},alerts or [],window_id=1,
            ml_result={'is_anomaly':ml,'anomaly_score':-.1 if ml else .1})
        record=db.connection.execute('SELECT MAX(id) FROM flow_records').fetchone()[0]
        db.connection.execute('UPDATE flow_records SET timestamp=? WHERE id=?',(stamp,record))
        db.connection.commit();db.connection.close();return record

    def test_empty_database_starts_without_synthetic_data(self):
        r=self.client.get('/api/dashboard');self.assertEqual(r.status_code,200)
        d=r.json['data'];self.assertEqual(d['summary']['packets'],0);self.assertEqual(d['series'],[])
        self.assertEqual(self.client.get('/').status_code,200)

    def test_packet_weighted_protocols_and_distinct_flags(self):
        self.add(ml=True)
        self.add('UDP',100,10000,alerts=[{'type':'HIGH_PACKET_RATE','severity':'MEDIUM'}],ml=True)
        self.add('ARP',2,120)
        d=self.client.get('/api/dashboard?range=all').json['data']
        for k,v in [('packets',112),('bytes',11120),('flagged',2),('rule_alerts',1),('endpoints',2)]:
            self.assertEqual(d['summary'][k],v)
        self.assertEqual((d['protocols'][0]['protocol'],d['protocols'][0]['packets']),('UDP',100))
        self.assertAlmostEqual(sum(r['bps']*d['interval']/8 for r in d['series']),11120)

    def test_range_uses_latest_record_clock(self):
        self.add(stamp='2026-01-02T10:00:00');self.add(stamp='2026-01-02T12:00:00')
        self.assertEqual(self.client.get('/api/dashboard?range=5m').json['data']['summary']['flows'],1)
        self.assertEqual(self.client.get('/api/dashboard?range=all').json['data']['summary']['flows'],2)

    def test_filters_pagination_and_details(self):
        for _ in range(27):self.add()
        record=self.add('UDP')
        d=self.client.get('/api/flows?range=all&page=2').json
        self.assertEqual(d['total'],28);self.assertEqual(len(d['data']),3)
        self.assertEqual(self.client.get('/api/flows?range=all&protocol=UDP').json['total'],1)
        self.assertEqual(self.client.get('/api/flows?q=192.0.2.1').json['total'],28)
        self.assertEqual(self.client.get(f'/api/flows/{record}').json['data']['family'],'IPv4')
        self.assertEqual(self.client.get('/api/flows/99999').status_code,404)

    def test_invalid_queries_and_literal_search(self):
        self.add()
        for url in ['/api/flows?page=nope','/api/flows?protocol=INVALID','/api/dashboard?range=nope','/api/flows?sort=DROP']:
            self.assertEqual(self.client.get(url).status_code,400)
        for query in ["' OR 1=1 --",'%']:
            self.assertEqual(self.client.get('/api/flows',query_string={'q':query}).json['total'],0)

    def test_csv_filter_and_formula_sanitization(self):
        self.add('TCP');self.add('UDP',source='=malicious')
        r=self.client.get('/api/export.csv?protocol=UDP')
        rows=list(csv.DictReader(io.StringIO(r.data.decode())))
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['protocol'],'UDP')
        self.assertEqual(rows[0]['source_ip'],"'=malicious")
        self.assertIn('attachment',r.headers['Content-Disposition'])
        self.assertEqual(self.client.get('/api/report.json').status_code,200)

    def test_ipv4_ipv6_and_point_to_point_subnets(self):
        for cidr,network,usable in [('192.168.1.10/26','192.168.1.0/26','62'),('192.0.2.0/31','192.0.2.0/31','2'),('192.0.2.1/32','192.0.2.1/32','1')]:
            d=self.client.get('/api/subnet',query_string={'cidr':cidr}).json['data']
            self.assertEqual((d['network'],d['usable']),(network,usable))
        d=self.client.get('/api/subnet?cidr=2001:db8::1/64').json['data']
        self.assertEqual(d['addresses'],str(2**64));self.assertIn('no broadcast',d['broadcast'])
        self.assertEqual(self.client.get('/api/subnet?cidr=bad').status_code,400)

    def test_capture_actions_are_same_origin_and_mocked(self):
        self.assertEqual(self.client.post('/api/capture',json={'action':'start'}).status_code,403)
        h={'X-AegisNet':'local-dashboard','Origin':'https://unrelated.example'}
        self.assertEqual(self.client.post('/api/capture',json={'action':'start'},headers=h).status_code,403)
        with patch.object(dashboard.capture_control,'start',return_value={'state':'starting'}) as start:
            r=self.client.post('/api/capture',json={'action':'start','interface':'3'},headers={'X-AegisNet':'local-dashboard'})
            self.assertEqual(r.status_code,200);start.assert_called_once_with('3')
        self.assertEqual(self.client.post('/api/capture',json={'action':'unknown'},headers={'X-AegisNet':'local-dashboard'}).status_code,400)


if __name__=='__main__':unittest.main()
