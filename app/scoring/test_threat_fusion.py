from app.scoring.threat_scorer import ThreatScorer


class TestFlow:

    def __init__(
        self,
        syn_count,
        packet_count,
        rst_count,
        packets_per_second,
        bytes_per_second
    ):

        self.syn_count = syn_count
        self.packet_count = packet_count
        self.rst_count = rst_count
        self._packets_per_second = packets_per_second
        self._bytes_per_second = bytes_per_second

    def packets_per_second(self):

        return self._packets_per_second

    def bytes_per_second(self):

        return self._bytes_per_second


flow = TestFlow(
    syn_count=150,
    packet_count=1500,
    rst_count=5,
    packets_per_second=1500,
    bytes_per_second=900000
)


alerts = [
    {
        "type": "SYN_FLOOD",
        "severity": "HIGH",
        "message": "High SYN activity detected."
    }
]


ml_result = {
    "is_anomaly": True,
    "prediction": -1,
    "anomaly_score": -0.05,
    "ml_confidence": 0.1667
}


scorer = ThreatScorer()

result = scorer.calculate(
    flow=flow,
    alerts=alerts,
    ml_result=ml_result
)


print("=" * 70)
print(
    "             AEGISNET THREAT FUSION TEST"
)
print("=" * 70)

print(
    f"Threat Score : "
    f"{result['score']}/100"
)

print(
    f"Severity     : "
    f"{result['severity']}"
)

print(
    f"ML Anomaly   : "
    f"{result['ml_anomaly']}"
)

print(
    f"ML Confidence: "
    f"{result['ml_confidence']:.4f}"
)

print()
print("Detection Reasons")
print("-" * 70)

for reason in result["reasons"]:

    print(
        f"- {reason}"
    )

print()
print("=" * 70)

print(
    "Threat fusion test completed."
)

print("=" * 70)