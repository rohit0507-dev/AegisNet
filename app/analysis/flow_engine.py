from collections import defaultdict
from datetime import datetime
from scapy.all import IP, IPv6, TCP, UDP


class Flow:

    def __init__(
        self,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    ):

        self.source_ip = source_ip
        self.destination_ip = destination_ip

        self.source_port = source_port
        self.destination_port = destination_port

        self.protocol = protocol

        self.packet_count = 0
        self.total_bytes = 0

        self.start_time = None
        self.last_time = None

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0

    def add_packet(self, packet):

        current_time = datetime.now()

        if self.start_time is None:
            self.start_time = current_time

        self.last_time = current_time

        self.packet_count += 1
        self.total_bytes += len(packet)

        if TCP in packet:

            flags = packet[TCP].flags

            if "S" in flags:
                self.syn_count += 1

            if "A" in flags:
                self.ack_count += 1

            if "F" in flags:
                self.fin_count += 1

            if "R" in flags:
                self.rst_count += 1

    def duration(self):

        if self.start_time is None:
            return 0

        if self.last_time is None:
            return 0

        duration = (
            self.last_time - self.start_time
        ).total_seconds()

        return max(duration, 0)

    def packets_per_second(self):

        duration = self.duration()

        if duration < 0.001:
            return 0

        return self.packet_count / duration

    def bytes_per_second(self):

        duration = self.duration()

        if duration < 0.001:
            return 0

        return self.total_bytes / duration

    def average_packet_size(self):

        if self.packet_count == 0:
            return 0

        return self.total_bytes / self.packet_count

    def syn_ratio(self):

        if self.packet_count == 0:
            return 0

        return self.syn_count / self.packet_count

    def ack_ratio(self):

        if self.packet_count == 0:
            return 0

        return self.ack_count / self.packet_count

    def rst_ratio(self):

        if self.packet_count == 0:
            return 0

        return self.rst_count / self.packet_count

    def fin_ratio(self):

        if self.packet_count == 0:
            return 0

        return self.fin_count / self.packet_count

    def get_features(self):

        return {

            "source_ip":
                self.source_ip,

            "destination_ip":
                self.destination_ip,

            "source_port":
                self.source_port,

            "destination_port":
                self.destination_port,

            "protocol":
                self.protocol,

            "packet_count":
                self.packet_count,

            "total_bytes":
                self.total_bytes,

            "duration":
                self.duration(),

            "packets_per_second":
                self.packets_per_second(),

            "bytes_per_second":
                self.bytes_per_second(),

            "average_packet_size":
                self.average_packet_size(),

            "syn_count":
                self.syn_count,

            "ack_count":
                self.ack_count,

            "fin_count":
                self.fin_count,

            "rst_count":
                self.rst_count,

            "syn_ratio":
                self.syn_ratio(),

            "ack_ratio":
                self.ack_ratio(),

            "fin_ratio":
                self.fin_ratio(),

            "rst_ratio":
                self.rst_ratio()
        }


class FlowEngine:

    def __init__(self):

        self.flows = defaultdict(lambda: None)

    def get_flow_key(self, packet):

        if IP in packet:

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        elif IPv6 in packet:

            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        else:

            return None

        if TCP in packet:

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            protocol = "TCP"

        elif UDP in packet:

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            protocol = "UDP"

        else:

            source_port = 0
            destination_port = 0
            protocol = "OTHER"

        return (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        )

    def process_packet(self, packet):

        key = self.get_flow_key(packet)

        if key is None:
            return

        if self.flows[key] is None:

            self.flows[key] = Flow(
                source_ip=key[0],
                destination_ip=key[1],
                source_port=key[2],
                destination_port=key[3],
                protocol=key[4]
            )

        self.flows[key].add_packet(packet)

    def get_all_features(self):

        return [
            flow.get_features()
            for flow in self.flows.values()
            if flow is not None
        ]

    def reset(self):

        self.flows.clear()


if __name__ == "__main__":

    engine = FlowEngine()

    print("=" * 70)
    print("             AEGISNET FLOW ENGINE")
    print("=" * 70)

    print("Flow engine initialized successfully.")

    print(
        f"Active flows: "
        f"{len(engine.flows)}"
    )