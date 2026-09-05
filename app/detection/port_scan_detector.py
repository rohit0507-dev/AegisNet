from collections import defaultdict


class PortScanDetector:

    def __init__(
        self,
        port_threshold=20,
        flow_threshold=10
    ):

        self.port_threshold = port_threshold
        self.flow_threshold = flow_threshold

    def detect(self, flows):

        source_data = defaultdict(
            lambda: {
                "ports": set(),
                "flows": 0,
                "destinations": set()
            }
        )

        for flow in flows:

            source_ip = flow["source_ip"]
            destination_port = flow["destination_port"]
            destination_ip = flow["destination_ip"]

            if destination_port == 0:
                continue

            source_data[source_ip]["ports"].add(
                destination_port
            )

            source_data[source_ip]["flows"] += 1

            source_data[source_ip]["destinations"].add(
                destination_ip
            )

        detections = []

        for source_ip, data in source_data.items():

            unique_ports = len(
                data["ports"]
            )

            flow_count = data["flows"]

            destination_count = len(
                data["destinations"]
            )

            if (
                unique_ports >= self.port_threshold
                and flow_count >= self.flow_threshold
            ):

                detections.append({
                    "source_ip": source_ip,
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "unique_ports": unique_ports,
                    "flow_count": flow_count,
                    "destination_count": destination_count,
                    "message":
                        "Source contacted an unusually "
                        "large number of destination ports."
                })

        return detections


if __name__ == "__main__":

    detector = PortScanDetector()

    test_flows = []

    for port in range(1, 31):

        test_flows.append({
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.100",
            "destination_port": port
        })

    detections = detector.detect(
        test_flows
    )

    print("=" * 70)
    print(
        "       AEGISNET PORT SCAN DETECTOR"
    )
    print("=" * 70)

    if detections:

        for detection in detections:

            print()
            print(
                f"Source IP          : "
                f"{detection['source_ip']}"
            )

            print(
                f"Unique Ports       : "
                f"{detection['unique_ports']}"
            )

            print(
                f"Flow Count         : "
                f"{detection['flow_count']}"
            )

            print(
                f"Destination Count  : "
                f"{detection['destination_count']}"
            )

            print(
                f"Severity            : "
                f"{detection['severity']}"
            )

            print(
                f"Detection           : "
                f"{detection['type']}"
            )

    else:

        print(
            "No port scan detected."
        )

    print()
    print("=" * 70)
    print(
        "Port scan detector test complete."
    )
    print("=" * 70)