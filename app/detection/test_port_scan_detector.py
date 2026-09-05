from app.detection.port_scan_detector import PortScanDetector


detector = PortScanDetector()


normal_flows = [
    {
        "source_ip": "192.168.1.20",
        "destination_ip": "192.168.1.100",
        "destination_port": 80
    },
    {
        "source_ip": "192.168.1.20",
        "destination_ip": "192.168.1.100",
        "destination_port": 443
    },
    {
        "source_ip": "192.168.1.20",
        "destination_ip": "192.168.1.100",
        "destination_port": 53
    },
    {
        "source_ip": "192.168.1.20",
        "destination_ip": "192.168.1.100",
        "destination_port": 8080
    }
]


scan_flows = []

for port in range(1, 31):

    scan_flows.append({
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.100",
        "destination_port": port
    })


normal_result = detector.detect(
    normal_flows
)

scan_result = detector.detect(
    scan_flows
)


print("=" * 70)
print(
    "       AEGISNET PORT SCAN DETECTOR TEST"
)
print("=" * 70)

print()
print(
    f"Normal traffic detections : "
    f"{len(normal_result)}"
)

print(
    f"Scan traffic detections   : "
    f"{len(scan_result)}"
)

print()

if len(normal_result) == 0:

    print(
        "PASS: Normal traffic was not classified as a port scan."
    )

else:

    print(
        "FAIL: Normal traffic triggered a port scan alert."
    )


if len(scan_result) > 0:

    print(
        "PASS: Port scan behavior was detected."
    )

else:

    print(
        "FAIL: Port scan behavior was not detected."
    )

print()
print("=" * 70)