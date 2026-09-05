from collections import defaultdict


class SourceContextEngine:

    def __init__(self):

        self.minimum_packets = 1

    def calculate(
        self,
        flows,
        window_features
    ):

        if not flows:

            return {}

        total_packets = max(
            window_features.get(
                "total_packets",
                0
            ),
            1
        )

        total_bytes = max(
            window_features.get(
                "total_bytes",
                0
            ),
            1
        )

        total_flows = max(
            window_features.get(
                "flow_count",
                0
            ),
            1
        )

        source_data = defaultdict(
            lambda: {
                "packet_count": 0,
                "total_bytes": 0,
                "flow_count": 0,
                "destination_ips": set(),
                "destination_ports": set(),
                "protocols": set(),
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0
            }
        )

        for flow in flows:

            source_ip = flow.get(
                "source_ip",
                "UNKNOWN"
            )

            packet_count = max(
                flow.get(
                    "packet_count",
                    0
                ),
                0
            )

            total_flow_bytes = max(
                flow.get(
                    "total_bytes",
                    0
                ),
                0
            )

            destination_ip = flow.get(
                "destination_ip"
            )

            destination_port = flow.get(
                "destination_port",
                0
            )

            protocol = flow.get(
                "protocol",
                "OTHER"
            )

            data = source_data[
                source_ip
            ]

            data["packet_count"] += (
                packet_count
            )

            data["total_bytes"] += (
                total_flow_bytes
            )

            data["flow_count"] += 1

            if destination_ip:

                data[
                    "destination_ips"
                ].add(
                    destination_ip
                )

            if destination_port not in (
                None,
                0
            ):

                data[
                    "destination_ports"
                ].add(
                    destination_port
                )

            data[
                "protocols"
            ].add(
                protocol
            )

            data[
                "syn_count"
            ] += flow.get(
                "syn_count",
                0
            )

            data[
                "ack_count"
            ] += flow.get(
                "ack_count",
                0
            )

            data[
                "fin_count"
            ] += flow.get(
                "fin_count",
                0
            )

            data[
                "rst_count"
            ] += flow.get(
                "rst_count",
                0
            )

        contexts = {}

        for source_ip, data in (
            source_data.items()
        ):

            packet_count = (
                data["packet_count"]
            )

            source_bytes = (
                data["total_bytes"]
            )

            flow_count = (
                data["flow_count"]
            )

            packet_share = (
                packet_count
                / total_packets
            )

            byte_share = (
                source_bytes
                / total_bytes
            )

            flow_share = (
                flow_count
                / total_flows
            )

            destination_count = len(
                data[
                    "destination_ips"
                ]
            )

            port_count = len(
                data[
                    "destination_ports"
                ]
            )

            protocol_count = len(
                data[
                    "protocols"
                ]
            )

            syn_count = data[
                "syn_count"
            ]

            ack_count = data[
                "ack_count"
            ]

            fin_count = data[
                "fin_count"
            ]

            rst_count = data[
                "rst_count"
            ]

            syn_ratio = (
                syn_count
                / packet_count
                if packet_count > 0
                else 0.0
            )

            ack_ratio = (
                ack_count
                / packet_count
                if packet_count > 0
                else 0.0
            )

            fin_ratio = (
                fin_count
                / packet_count
                if packet_count > 0
                else 0.0
            )

            rst_ratio = (
                rst_count
                / packet_count
                if packet_count > 0
                else 0.0
            )

            activity_score = (
                packet_share * 0.40
                +
                byte_share * 0.30
                +
                flow_share * 0.15
                +
                min(
                    destination_count / 10,
                    1.0
                ) * 0.075
                +
                min(
                    port_count / 20,
                    1.0
                ) * 0.075
            )

            activity_score = min(
                activity_score,
                1.0
            )

            contexts[source_ip] = {

                "source_ip":
                    source_ip,

                "packet_count":
                    packet_count,

                "total_bytes":
                    source_bytes,

                "flow_count":
                    flow_count,

                "destination_count":
                    destination_count,

                "port_count":
                    port_count,

                "protocol_count":
                    protocol_count,

                "packet_share":
                    packet_share,

                "byte_share":
                    byte_share,

                "flow_share":
                    flow_share,

                "syn_count":
                    syn_count,

                "ack_count":
                    ack_count,

                "fin_count":
                    fin_count,

                "rst_count":
                    rst_count,

                "syn_ratio":
                    syn_ratio,

                "ack_ratio":
                    ack_ratio,

                "fin_ratio":
                    fin_ratio,

                "rst_ratio":
                    rst_ratio,

                "activity_score":
                    activity_score

            }

        return contexts

    def get_source(
        self,
        contexts,
        source_ip
    ):

        return contexts.get(
            source_ip,
            {
                "source_ip":
                    source_ip,

                "packet_count":
                    0,

                "total_bytes":
                    0,

                "flow_count":
                    0,

                "destination_count":
                    0,

                "port_count":
                    0,

                "protocol_count":
                    0,

                "packet_share":
                    0.0,

                "byte_share":
                    0.0,

                "flow_share":
                    0.0,

                "syn_count":
                    0,

                "ack_count":
                    0,

                "fin_count":
                    0,

                "rst_count":
                    0,

                "syn_ratio":
                    0.0,

                "ack_ratio":
                    0.0,

                "fin_ratio":
                    0.0,

                "rst_ratio":
                    0.0,

                "activity_score":
                    0.0

            }
        )

    def rank_sources(
        self,
        contexts
    ):

        return sorted(
            contexts.values(),
            key=lambda item:
                item["activity_score"],
            reverse=True
        )


if __name__ == "__main__":

    engine = SourceContextEngine()

    test_flows = [

        {
            "source_ip":
                "192.168.1.10",

            "destination_ip":
                "8.8.8.8",

            "destination_port":
                443,

            "protocol":
                "TCP",

            "packet_count":
                100,

            "total_bytes":
                10000,

            "syn_count":
                5,

            "ack_count":
                80,

            "fin_count":
                5,

            "rst_count":
                2
        },

        {
            "source_ip":
                "192.168.1.10",

            "destination_ip":
                "1.1.1.1",

            "destination_port":
                443,

            "protocol":
                "TCP",

            "packet_count":
                50,

            "total_bytes":
                5000,

            "syn_count":
                2,

            "ack_count":
                40,

            "fin_count":
                3,

            "rst_count":
                1
        },

        {
            "source_ip":
                "192.168.1.20",

            "destination_ip":
                "10.0.0.5",

            "destination_port":
                22,

            "protocol":
                "TCP",

            "packet_count":
                10,

            "total_bytes":
                1000,

            "syn_count":
                1,

            "ack_count":
                5,

            "fin_count":
                1,

            "rst_count":
                0
        }

    ]

    window_features = {

        "total_packets":
            160,

        "total_bytes":
            16000,

        "flow_count":
            3

    }

    contexts = engine.calculate(
        test_flows,
        window_features
    )

    print("=" * 85)
    print(
        "             AEGISNET SOURCE CONTEXT ENGINE"
    )
    print("=" * 85)

    print()

    print("SOURCE CONTEXT")

    print("-" * 85)

    for source_ip, context in (
        contexts.items()
    ):

        print()

        print(
            f"Source IP           : "
            f"{source_ip}"
        )

        print(
            f"Packets             : "
            f"{context['packet_count']}"
        )

        print(
            f"Bytes               : "
            f"{context['total_bytes']}"
        )

        print(
            f"Flows               : "
            f"{context['flow_count']}"
        )

        print(
            f"Destinations        : "
            f"{context['destination_count']}"
        )

        print(
            f"Ports               : "
            f"{context['port_count']}"
        )

        print(
            f"Packet Share        : "
            f"{context['packet_share']:.4f}"
        )

        print(
            f"Byte Share          : "
            f"{context['byte_share']:.4f}"
        )

        print(
            f"Flow Share          : "
            f"{context['flow_share']:.4f}"
        )

        print(
            f"SYN Ratio           : "
            f"{context['syn_ratio']:.4f}"
        )

        print(
            f"RST Ratio           : "
            f"{context['rst_ratio']:.4f}"
        )

        print(
            f"Activity Score      : "
            f"{context['activity_score']:.4f}"
        )

    print()

    print("SOURCE RANKING")

    print("-" * 85)

    ranked = engine.rank_sources(
        contexts
    )

    for index, source in enumerate(
        ranked,
        start=1
    ):

        print(
            f"{index}. "
            f"{source['source_ip']:<20} "
            f"Activity="
            f"{source['activity_score']:.4f}"
        )

    print()

    print("=" * 85)

    print(
        "Source context engine initialized successfully."
    )

    print("=" * 85)