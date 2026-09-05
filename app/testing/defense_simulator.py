from app.response.response_controller import ResponseController


class SimulatedFlow:

    def __init__(
        self,
        syn_count=0,
        packet_count=0,
        rst_count=0,
        packets_per_second=0,
        bytes_per_second=0
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


def calculate_threat(flow):

    score = 0

    if flow.syn_count >= 100:
        score += 35

    if flow.packet_count > 1000:
        score += 20

    if flow.packets_per_second() > 500:
        score += 15

    if flow.bytes_per_second() > 5_000_000:
        score += 10

    if flow.packet_count >= 20:

        rst_rate = (
            flow.rst_count /
            flow.packet_count
        )

        if rst_rate > 0.5:
            score += 15

    return min(score, 100)


def classify(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH_RISK"

    if score >= 30:
        return "SUSPICIOUS"

    return "NORMAL"


def run_scenario(
    controller,
    name,
    source_ip,
    flow,
    ml_anomaly=False
):

    score = calculate_threat(flow)

    state = classify(score)

    result = controller.process(
        source_ip=source_ip,
        threat_score=score,
        ml_result={
            "is_anomaly": ml_anomaly,
            "anomaly_score": -0.25
            if ml_anomaly
            else 0.05,
            "ml_confidence": 0.85
            if ml_anomaly
            else 0.0
        },
        alerts=[]
    )

    action = result[
        "decision"
    ]["action"]

    print()
    print("=" * 70)
    print(
        f"SCENARIO: {name}"
    )
    print("=" * 70)

    print(
        f"Source IP    : {source_ip}"
    )

    print(
        f"Threat Score : {score}/100"
    )

    print(
        f"Threat State : {state}"
    )

    print(
        f"Action       : {action}"
    )

    if result["monitor"]:

        print(
            f"Effectiveness: "
            f"{result['monitor']['effectiveness']}"
        )

        print(
            f"Recommendation: "
            f"{result['monitor']['recommendation']}"
        )


def main():

    controller = ResponseController(
        simulation_mode=True
    )

    print()
    print("=" * 70)
    print(
        "        AEGISNET DEFENSE SIMULATION"
    )
    print("=" * 70)

    normal_flow = SimulatedFlow(
        syn_count=2,
        packet_count=100,
        packets_per_second=20,
        bytes_per_second=20000
    )

    run_scenario(
        controller,
        "NORMAL TRAFFIC",
        "192.168.100.10",
        normal_flow
    )

    suspicious_flow = SimulatedFlow(
        syn_count=20,
        packet_count=2000,
        packets_per_second=600,
        bytes_per_second=500000
    )

    run_scenario(
        controller,
        "SUSPICIOUS TRAFFIC",
        "192.168.100.20",
        suspicious_flow
    )

    high_risk_flow = SimulatedFlow(
        syn_count=80,
        packet_count=2000,
        rst_count=1100,
        packets_per_second=700,
        bytes_per_second=6000000
    )

    run_scenario(
        controller,
        "HIGH-RISK TRAFFIC",
        "192.168.100.30",
        high_risk_flow,
        ml_anomaly=False
    )

    critical_flow = SimulatedFlow(
        syn_count=150,
        packet_count=2000,
        rst_count=5,
        packets_per_second=1200,
        bytes_per_second=8000000
    )

    run_scenario(
        controller,
        "CRITICAL TRAFFIC",
        "192.168.100.40",
        critical_flow,
        ml_anomaly=True
    )

    run_scenario(
        controller,
        "PERSISTENT CRITICAL TRAFFIC",
        "192.168.100.40",
        critical_flow,
        ml_anomaly=True
    )

    recovery_flow = SimulatedFlow(
        syn_count=2,
        packet_count=100,
        packets_per_second=20,
        bytes_per_second=20000
    )

    run_scenario(
        controller,
        "RECOVERED TRAFFIC",
        "192.168.100.40",
        recovery_flow
    )

    print()
    print("=" * 70)
    print(
        "ACTIVE RESPONSES"
    )
    print("=" * 70)

    active = (
        controller.get_active_responses()
    )

    if not active:

        print(
            "No active responses."
        )

    else:

        for source_ip, response in active.items():

            print(
                f"{source_ip} -> "
                f"{response['action']}"
            )

    print()
    print("=" * 70)
    print(
        "DEFENSE SIMULATION COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":

    main()