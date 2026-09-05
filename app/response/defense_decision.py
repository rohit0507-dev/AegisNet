class DefenseDecisionEngine:

    def __init__(self, simulation_mode=True):

        self.simulation_mode = simulation_mode

        self.actions = {
            "NORMAL": "MONITOR",
            "SUSPICIOUS": "MONITOR_AND_LOG",
            "HIGH_RISK": "TEMPORARY_LIMIT",
            "CRITICAL": "TEMPORARY_BLOCK"
        }

    def decide(self, state_result, ml_result=None, alerts=None):

        state = state_result["current_state"]
        score = state_result["threat_score"]

        if ml_result is None:
            ml_result = {
                "is_anomaly": False,
                "anomaly_score": 0
            }

        if alerts is None:
            alerts = []

        action = self.actions.get(
            state,
            "MONITOR"
        )

        reasons = []

        if score >= 80:
            reasons.append(
                "Critical threat score"
            )

        elif score >= 60:
            reasons.append(
                "High threat score"
            )

        elif score >= 30:
            reasons.append(
                "Suspicious threat score"
            )

        if ml_result["is_anomaly"]:
            reasons.append(
                "ML anomaly detected"
            )

        for alert in alerts:
            reasons.append(
                alert["type"]
            )

        if self.simulation_mode:

            mode = "SIMULATION"

        else:

            mode = "ACTIVE"

        return {
            "state": state,
            "threat_score": score,
            "action": action,
            "mode": mode,
            "reasons": reasons
        }


if __name__ == "__main__":

    engine = DefenseDecisionEngine(
        simulation_mode=True
    )

    print("=" * 70)
    print("          AEGISNET DEFENSE DECISION ENGINE")
    print("=" * 70)

    test_states = [
        {
            "current_state": "NORMAL",
            "threat_score": 10
        },
        {
            "current_state": "SUSPICIOUS",
            "threat_score": 40
        },
        {
            "current_state": "HIGH_RISK",
            "threat_score": 65
        },
        {
            "current_state": "CRITICAL",
            "threat_score": 90
        }
    ]

    for state in test_states:

        result = engine.decide(
            state
        )

        print()
        print(
            f"State        : "
            f"{result['state']}"
        )

        print(
            f"Threat Score : "
            f"{result['threat_score']}"
        )

        print(
            f"Action       : "
            f"{result['action']}"
        )

        print(
            f"Mode         : "
            f"{result['mode']}"
        )

    print()
    print("=" * 70)
    print("Defense decision engine initialized successfully.")
    print("=" * 70)