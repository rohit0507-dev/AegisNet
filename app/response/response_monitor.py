class ResponseMonitor:

    IMPROVEMENT_THRESHOLD = 0.20

    def __init__(self):

        self.response_history = []

    def evaluate(
        self,
        source_ip,
        previous_score,
        current_score,
        action
    ):

        if previous_score <= 0:

            improvement_ratio = 0

        else:

            improvement_ratio = (
                previous_score - current_score
            ) / previous_score

        if improvement_ratio >= self.IMPROVEMENT_THRESHOLD:

            effectiveness = "EFFECTIVE"
            recommendation = "RESTORE"

        elif current_score >= 80:

            effectiveness = "INEFFECTIVE"
            recommendation = "ESCALATE"

        else:

            effectiveness = "PARTIALLY_EFFECTIVE"
            recommendation = "OBSERVE"

        result = {
            "source_ip": source_ip,
            "previous_score": previous_score,
            "current_score": current_score,
            "improvement_ratio": improvement_ratio,
            "action": action,
            "effectiveness": effectiveness,
            "recommendation": recommendation
        }

        self.response_history.append(
            result
        )

        return result

    def get_history(self):

        return self.response_history


if __name__ == "__main__":

    monitor = ResponseMonitor()

    print("=" * 70)
    print("          AEGISNET RESPONSE MONITOR TEST")
    print("=" * 70)

    test_cases = [
        {
            "source_ip": "192.168.1.100",
            "previous_score": 90,
            "current_score": 30,
            "action": "TEMPORARY_BLOCK"
        },
        {
            "source_ip": "192.168.1.101",
            "previous_score": 85,
            "current_score": 82,
            "action": "TEMPORARY_BLOCK"
        },
        {
            "source_ip": "192.168.1.102",
            "previous_score": 70,
            "current_score": 60,
            "action": "TEMPORARY_LIMIT"
        }
    ]

    for test in test_cases:

        result = monitor.evaluate(
            source_ip=test["source_ip"],
            previous_score=test["previous_score"],
            current_score=test["current_score"],
            action=test["action"]
        )

        print()
        print(
            f"Source IP          : "
            f"{result['source_ip']}"
        )

        print(
            f"Previous Score     : "
            f"{result['previous_score']}"
        )

        print(
            f"Current Score      : "
            f"{result['current_score']}"
        )

        print(
            f"Improvement        : "
            f"{result['improvement_ratio'] * 100:.2f}%"
        )

        print(
            f"Action             : "
            f"{result['action']}"
        )

        print(
            f"Effectiveness      : "
            f"{result['effectiveness']}"
        )

        print(
            f"Recommendation     : "
            f"{result['recommendation']}"
        )

    print()
    print("=" * 70)
    print("Response monitor test completed.")
    print("=" * 70)