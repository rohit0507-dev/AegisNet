class WindowFeatureEngine:

    def calculate(self, flows):

        if not flows:

            return {
                "flow_count": 0,
                "total_packets": 0,
                "total_bytes": 0,

                "unique_source_ips": 0,
                "unique_destination_ips": 0,
                "unique_destination_ports": 0,

                "tcp_flows": 0,
                "udp_flows": 0,

                "average_packet_size": 0,
                "average_packets_per_second": 0,
                "average_bytes_per_second": 0,

                "total_syn": 0,
                "total_ack": 0,
                "total_fin": 0,
                "total_rst": 0,

                "window_syn_ratio": 0,
                "window_ack_ratio": 0,
                "window_fin_ratio": 0,
                "window_rst_ratio": 0
            }

        flow_count = len(flows)

        total_packets = sum(
            flow["packet_count"]
            for flow in flows
        )

        total_bytes = sum(
            flow["total_bytes"]
            for flow in flows
        )

        source_ips = {
            flow["source_ip"]
            for flow in flows
        }

        destination_ips = {
            flow["destination_ip"]
            for flow in flows
        }

        destination_ports = {
            flow["destination_port"]
            for flow in flows
            if flow["destination_port"] != 0
        }

        tcp_flows = sum(
            1
            for flow in flows
            if flow["protocol"] == "TCP"
        )

        udp_flows = sum(
            1
            for flow in flows
            if flow["protocol"] == "UDP"
        )

        average_packet_size = (
            total_bytes / total_packets
            if total_packets > 0
            else 0
        )

        average_packets_per_second = (
            sum(
                flow["packets_per_second"]
                for flow in flows
            ) / flow_count
        )

        average_bytes_per_second = (
            sum(
                flow["bytes_per_second"]
                for flow in flows
            ) / flow_count
        )

        total_syn = sum(
            flow["syn_count"]
            for flow in flows
        )

        total_ack = sum(
            flow["ack_count"]
            for flow in flows
        )

        total_fin = sum(
            flow["fin_count"]
            for flow in flows
        )

        total_rst = sum(
            flow["rst_count"]
            for flow in flows
        )

        window_syn_ratio = (
            total_syn / total_packets
            if total_packets > 0
            else 0
        )

        window_ack_ratio = (
            total_ack / total_packets
            if total_packets > 0
            else 0
        )

        window_fin_ratio = (
            total_fin / total_packets
            if total_packets > 0
            else 0
        )

        window_rst_ratio = (
            total_rst / total_packets
            if total_packets > 0
            else 0
        )

        return {

            "flow_count": flow_count,

            "total_packets": total_packets,

            "total_bytes": total_bytes,

            "unique_source_ips":
                len(source_ips),

            "unique_destination_ips":
                len(destination_ips),

            "unique_destination_ports":
                len(destination_ports),

            "tcp_flows": tcp_flows,

            "udp_flows": udp_flows,

            "average_packet_size":
                average_packet_size,

            "average_packets_per_second":
                average_packets_per_second,

            "average_bytes_per_second":
                average_bytes_per_second,

            "total_syn": total_syn,

            "total_ack": total_ack,

            "total_fin": total_fin,

            "total_rst": total_rst,

            "window_syn_ratio":
                window_syn_ratio,

            "window_ack_ratio":
                window_ack_ratio,

            "window_fin_ratio":
                window_fin_ratio,

            "window_rst_ratio":
                window_rst_ratio
        }


if __name__ == "__main__":

    engine = WindowFeatureEngine()

    features = engine.calculate([])

    print("=" * 70)
    print("          AEGISNET WINDOW FEATURE ENGINE")
    print("=" * 70)

    for key, value in features.items():

        print(
            f"{key:<32}: {value}"
        )

    print("=" * 70)
    print("Window feature engine initialized successfully.")