class RuleEngine:

    def __init__(self):

        self.rules = {
            "SYN_FLOOD": True,
            "HIGH_PACKET_RATE": True,
            "HIGH_BANDWIDTH": True,
            "HIGH_RST_RATE": True,
            "PORT_SCAN": True
        }

    def calculate_rst_rate(self, flow):

        if flow.packet_count == 0:
            return 0

        return flow.rst_count / flow.packet_count

    def detect(self, flow):

        alerts = []

        # ---------------------------------------------
        # SYN FLOOD
        # ---------------------------------------------

        if self.rules["SYN_FLOOD"]:

            if (
                flow.syn_count >= 100
                and flow.ack_count < flow.syn_count * 0.2
            ):

                alerts.append({
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message":
                        "High number of SYN packets "
                        "with low ACK response."
                })

        # ---------------------------------------------
        # HIGH PACKET RATE
        # ---------------------------------------------

        if self.rules["HIGH_PACKET_RATE"]:

            if flow.packets_per_second() > 1000:

                alerts.append({
                    "type": "HIGH_PACKET_RATE",
                    "severity": "MEDIUM",
                    "message":
                        "Unusually high packet "
                        "transmission rate detected."
                })

        # ---------------------------------------------
        # HIGH BANDWIDTH
        # ---------------------------------------------

        if self.rules["HIGH_BANDWIDTH"]:

            if flow.bytes_per_second() > 10_000_000:

                alerts.append({
                    "type": "HIGH_BANDWIDTH",
                    "severity": "MEDIUM",
                    "message":
                        "Unusually high bandwidth "
                        "consumption detected."
                })

        # ---------------------------------------------
        # HIGH RST RATE
        # ---------------------------------------------

        if self.rules["HIGH_RST_RATE"]:

            rst_rate = self.calculate_rst_rate(flow)

            if (
                flow.packet_count >= 20
                and rst_rate > 0.5
            ):

                alerts.append({
                    "type": "HIGH_RST_RATE",
                    "severity": "MEDIUM",
                    "message":
                        "High percentage of TCP "
                        "reset packets detected."
                })

        # ---------------------------------------------
        # PORT SCAN
        # ---------------------------------------------

        if self.rules["PORT_SCAN"]:

            unique_ports = getattr(
                flow,
                "unique_destination_ports",
                0
            )

            if unique_ports >= 20:

                alerts.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "message":
                        "Large number of destination "
                        "ports contacted by the source."
                })

        if getattr(flow, "protocol", None) in {"ICMP", "ICMPv6"} and flow.packet_count >= 200 and flow.packets_per_second() > 100:
            alerts.append({"type": "ICMP_FLOOD", "severity": "HIGH",
                           "message": "Sustained high-rate ICMP flow; investigate possible ping flood."})

        return alerts


if __name__ == "__main__":

    print("=" * 70)
    print(
        "        AEGISNET RULE ENGINE"
    )
    print("=" * 70)

    print(
        "Rules enabled:"
    )

    print(
        "- SYN Flood"
    )

    print(
        "- High Packet Rate"
    )

    print(
        "- High Bandwidth"
    )

    print(
        "- High RST Rate"
    )

    print(
        "- Port Scan"
    )

    print()
    print(
        "Rule-based IDS initialized successfully."
    )