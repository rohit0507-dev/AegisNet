class ResponsePolicy:

    def __init__(self):

        self.policies = {
            "NORMAL": "MONITOR",
            "SUSPICIOUS": "MONITOR_AND_LOG",
            "HIGH_RISK": "TEMPORARY_LIMIT",
            "CRITICAL": "TEMPORARY_BLOCK"
        }

    def select_action(
        self,
        state,
        threat_score,
        ml_anomaly=False,
        alert_count=0,
        previous_action=None,
        previous_effectiveness=None
    ):

        reasons = []

        if state == "NORMAL":

            action = "MONITOR"

            reasons.append(
                "Threat level is within normal range"
            )

        elif state == "SUSPICIOUS":

            action = "MONITOR_AND_LOG"

            reasons.append(
                "Suspicious behavior detected"
            )

            if ml_anomaly:

                reasons.append(
                    "ML detected anomalous behavior"
                )

        elif state == "HIGH_RISK":

            action = "TEMPORARY_LIMIT"

            reasons.append(
                "High-risk network behavior detected"
            )

            if ml_anomaly:

                reasons.append(
                    "ML anomaly supports defensive action"
                )

            if alert_count > 0:

                reasons.append(
                    "Rule-based alerts detected"
                )

        elif state == "CRITICAL":

            action = "TEMPORARY_BLOCK"

            reasons.append(
                "Critical threat level detected"
            )

            if ml_anomaly:

                reasons.append(
                    "ML anomaly detected"
                )

            if alert_count > 0:

                reasons.append(
                    "Multiple detection signals present"
                )

        else:

            action = "MONITOR"

            reasons.append(
                "Unknown state; safe monitoring selected"
            )

        if (
            previous_effectiveness == "INEFFECTIVE"
            and previous_action == "TEMPORARY_BLOCK"
        ):

            action = "QUARANTINE"

            reasons.append(
                "Previous block response was ineffective"
            )

            reasons.append(
                "Escalating to simulated quarantine"
            )

        elif (
            previous_effectiveness == "INEFFECTIVE"
            and previous_action == "TEMPORARY_LIMIT"
        ):

            action = "TEMPORARY_BLOCK"

            reasons.append(
                "Previous limiting response was ineffective"
            )

            reasons.append(
                "Escalating to temporary block"
            )

        elif (
            previous_effectiveness == "PARTIALLY_EFFECTIVE"
        ):

            action = previous_action

            reasons.append(
                "Previous response partially effective"
            )

            reasons.append(
                "Maintaining current defensive action"
            )

        return {
            "action": action,
            "threat_score": threat_score,
            "reasons": reasons
        }


if __name__ == "__main__":

    policy = ResponsePolicy()

    print("=" * 70)
    print("             AEGISNET RESPONSE POLICY TEST")
    print("=" * 70)

    test_cases = [
        {
            "name": "Normal traffic",
            "state": "NORMAL",
            "score": 15,
            "ml": False,
            "alerts": 0
        },
        {
            "name": "Suspicious traffic",
            "state": "SUSPICIOUS",
            "score": 40,
            "ml": True,
            "alerts": 0
        },
        {
            "name": "High-risk traffic",
            "state": "HIGH_RISK",
            "score": 65,
            "ml": True,
            "alerts": 1
        },
        {
            "name": "Critical traffic",
            "state": "CRITICAL",
            "score": 90,
            "ml": True,
            "alerts": 2
        },
        {
            "name": "Failed block",
            "state": "CRITICAL",
            "score": 88,
            "ml": True,
            "alerts": 2,
            "previous_action": "TEMPORARY_BLOCK",
            "previous_effectiveness": "INEFFECTIVE"
        },
        {
            "name": "Partial response",
            "state": "HIGH_RISK",
            "score": 62,
            "ml": True,
            "alerts": 1,
            "previous_action": "TEMPORARY_LIMIT",
            "previous_effectiveness": "PARTIALLY_EFFECTIVE"
        }
    ]

    for test in test_cases:

        result = policy.select_action(
            state=test["state"],
            threat_score=test["score"],
            ml_anomaly=test["ml"],
            alert_count=test["alerts"],
            previous_action=test.get(
                "previous_action"
            ),
            previous_effectiveness=test.get(
                "previous_effectiveness"
            )
        )

        print()
        print(
            f"Test           : "
            f"{test['name']}"
        )

        print(
            f"Threat Score   : "
            f"{test['score']}"
        )

        print(
            f"Selected Action: "
            f"{result['action']}"
        )

        print("Reasons:")

        for reason in result["reasons"]:

            print(
                f"  - {reason}"
            )

    print()
    print("=" * 70)
    print("Response policy test completed.")
    print("=" * 70)