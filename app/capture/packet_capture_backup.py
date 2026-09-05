from scapy.all import sniff, conf

from app.analysis.flow_engine import FlowEngine
from app.analysis.window_feature_engine import WindowFeatureEngine
from app.detection.rule_engine import RuleEngine
from app.scoring.threat_scorer import ThreatScorer
from app.analysis.window_manager import WindowManager
from app.database.database import Database


INTERFACE_INDEX = 16
CAPTURE_INTERFACE = conf.ifaces.dev_from_index(INTERFACE_INDEX)


def start_capture():

    print("=" * 70)
    print("             AEGISNET PACKET CAPTURE ENGINE")
    print("=" * 70)
    print("Interface       : Wi-Fi")
    print(f"Interface ID    : {INTERFACE_INDEX}")
    print(f"Capture Device  : {CAPTURE_INTERFACE}")
    print("Status          : CAPTURING")
    print("Analysis Window : 5 seconds")
    print("Database        : ENABLED")
    print("ML Features     : ENABLED")
    print("Window Features : ENABLED")
    print("Press CTRL+C to stop.")
    print()

    flow_engine = FlowEngine()
    window_feature_engine = WindowFeatureEngine()
    rule_engine = RuleEngine()
    threat_scorer = ThreatScorer()
    window_manager = WindowManager(5)
    database = Database()

    window_number = 0

    def process_window():

        nonlocal window_number

        window_number += 1

        flows = flow_engine.get_all_features()

        window_features = (
            window_feature_engine.calculate(flows)
        )

        total_packets = window_features["total_packets"]
        total_bytes = window_features["total_bytes"]

        highest_score = 0
        highest_severity = "LOW"
        alerts_count = 0

        for features in flows:

            class FlowData:
                pass

            flow = FlowData()

            flow.source_ip = features["source_ip"]
            flow.destination_ip = features["destination_ip"]

            flow.source_port = features["source_port"]
            flow.destination_port = features["destination_port"]

            flow.protocol = features["protocol"]

            flow.packet_count = features["packet_count"]
            flow.total_bytes = features["total_bytes"]

            flow.syn_count = features["syn_count"]
            flow.ack_count = features["ack_count"]
            flow.fin_count = features["fin_count"]
            flow.rst_count = features["rst_count"]

            flow.packets_per_second = (
                lambda: features["packets_per_second"]
            )

            flow.bytes_per_second = (
                lambda: features["bytes_per_second"]
            )

            alerts = rule_engine.detect(flow)

            threat = threat_scorer.calculate(
                flow,
                alerts
            )

            database.insert_flow(
                features,
                threat,
                alerts,
                window_number
            )

            if threat["score"] > highest_score:

                highest_score = threat["score"]
                highest_severity = threat["severity"]

            alerts_count += len(alerts)

        print("\n" + "=" * 70)
        print(f"             AEGISNET WINDOW #{window_number}")
        print("=" * 70)

        print(f"Flows Detected       : {window_features['flow_count']}")
        print(f"Total Packets        : {total_packets}")
        print(f"Total Bytes          : {total_bytes}")

        print(
            f"Unique Sources       : "
            f"{window_features['unique_source_ips']}"
        )

        print(
            f"Unique Destinations  : "
            f"{window_features['unique_destination_ips']}"
        )

        print(
            f"Unique Dest. Ports   : "
            f"{window_features['unique_destination_ports']}"
        )

        print(
            f"TCP Flows            : "
            f"{window_features['tcp_flows']}"
        )

        print(
            f"UDP Flows            : "
            f"{window_features['udp_flows']}"
        )

        print(
            f"Window SYN Ratio     : "
            f"{window_features['window_syn_ratio']:.4f}"
        )

        print(
            f"Window RST Ratio     : "
            f"{window_features['window_rst_ratio']:.4f}"
        )

        print(f"Alerts               : {alerts_count}")
        print(f"Highest Score        : {highest_score}/100")
        print(f"Highest Severity      : {highest_severity}")

        print(
            f"Database Records     : "
            f"{database.get_record_count()}"
        )

        print("=" * 70)

        flow_engine.reset()
        window_manager.reset()

    def handle_packet(packet):

        flow_engine.process_packet(packet)

        if window_manager.is_expired():

            process_window()

    try:

        sniff(
            iface=CAPTURE_INTERFACE,
            prn=handle_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 70)
        print("        AEGISNET CAPTURE STOPPED")
        print("=" * 70)

        database.close()


if __name__ == "__main__":

    start_capture()