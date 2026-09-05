class ThreatStateEngine:

    NORMAL_THRESHOLD = 30
    HIGH_RISK_THRESHOLD = 60
    CRITICAL_THRESHOLD = 80

    RECOVERY_THRESHOLD = 45

    def __init__(self):

        self.current_state = "NORMAL"

        self.previous_score = 0

        self.state_history = []

    def evaluate(self, threat_score):

        previous_state = self.current_state

        if self.current_state == "NORMAL":

            if threat_score >= self.CRITICAL_THRESHOLD:

                self.current_state = "CRITICAL"

            elif threat_score >= self.HIGH_RISK_THRESHOLD:

                self.current_state = "HIGH_RISK"

            elif threat_score >= self.NORMAL_THRESHOLD:

                self.current_state = "SUSPICIOUS"

        elif self.current_state == "SUSPICIOUS":

            if threat_score >= self.CRITICAL_THRESHOLD:

                self.current_state = "CRITICAL"

            elif threat_score >= self.HIGH_RISK_THRESHOLD:

                self.current_state = "HIGH_RISK"

            elif threat_score < self.RECOVERY_THRESHOLD:

                self.current_state = "NORMAL"

        elif self.current_state == "HIGH_RISK":

            if threat_score >= self.CRITICAL_THRESHOLD:

                self.current_state = "CRITICAL"

            elif threat_score < self.RECOVERY_THRESHOLD:

                self.current_state = "NORMAL"

            elif threat_score < self.HIGH_RISK_THRESHOLD:

                self.current_state = "SUSPICIOUS"

        elif self.current_state == "CRITICAL":

            if threat_score < self.RECOVERY_THRESHOLD:

                self.current_state = "NORMAL"

            elif threat_score < self.HIGH_RISK_THRESHOLD:

                self.current_state = "SUSPICIOUS"

        self.previous_score = threat_score

        transition = (
            previous_state != self.current_state
        )

        result = {
            "previous_state": previous_state,
            "current_state": self.current_state,
            "threat_score": threat_score,
            "transition": transition
        }

        self.state_history.append(result)

        return result

    def reset(self):

        self.current_state = "NORMAL"

        self.previous_score = 0

        self.state_history.clear()


if __name__ == "__main__":

    engine = ThreatStateEngine()

    print("=" * 70)
    print("             AEGISNET THREAT STATE ENGINE")
    print("=" * 70)

    test_scores = [
        10,
        35,
        65,
        85,
        70,
        50,
        40,
        20
    ]

    for score in test_scores:

        result = engine.evaluate(score)

        print(
            f"Score: {score:3} | "
            f"{result['previous_state']:10} -> "
            f"{result['current_state']:10}"
        )

    print("=" * 70)
    print("Threat state engine initialized successfully.")
    print("=" * 70)