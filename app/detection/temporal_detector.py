from collections import defaultdict, deque


class TemporalDetector:

    def __init__(
        self,
        strong_threshold=0.60,
        very_strong_threshold=0.85,
        persistence_threshold=3,
        history_size=10
    ):

        self.strong_threshold = (
            strong_threshold
        )

        self.very_strong_threshold = (
            very_strong_threshold
        )

        self.persistence_threshold = (
            persistence_threshold
        )

        self.history_size = history_size

        self.history = defaultdict(
            lambda: deque(
                maxlen=self.history_size
            )
        )

        self.last_result = {}

    def _classify_score(
        self,
        anomaly_score
    ):

        score = float(
            anomaly_score
        )

        if score >= self.very_strong_threshold:

            return "VERY_STRONG"

        if score >= self.strong_threshold:

            return "STRONG"

        if score > 0.0:

            return "WEAK"

        return "NORMAL"

    def _calculate_streak(
        self,
        history
    ):

        streak = 0

        for state in reversed(
            history
        ):

            if state in (
                "STRONG",
                "VERY_STRONG"
            ):

                streak += 1

            else:

                break

        return streak

    def _calculate_strong_count(
        self,
        history
    ):

        count = 0

        for state in history:

            if state in (
                "STRONG",
                "VERY_STRONG"
            ):

                count += 1

        return count

    def _calculate_very_strong_count(
        self,
        history
    ):

        count = 0

        for state in history:

            if state == "VERY_STRONG":

                count += 1

        return count

    def _calculate_persistence_ratio(
        self,
        history
    ):

        if not history:

            return 0.0

        strong_count = (
            self._calculate_strong_count(
                history
            )
        )

        return (
            strong_count
            / len(history)
        )

    def _calculate_temporal_confidence(
        self,
        strong_streak,
        persistence_ratio,
        very_strong_count
    ):

        streak_score = min(
            strong_streak
            / self.persistence_threshold,
            1.0
        )

        persistence_score = min(
            persistence_ratio,
            1.0
        )

        intensity_score = min(
            very_strong_count
            / max(
                self.persistence_threshold,
                1
            ),
            1.0
        )

        confidence = (

            streak_score * 0.50

            +

            persistence_score * 0.30

            +

            intensity_score * 0.20

        )

        if confidence >= 0.85:

            return "VERY_HIGH"

        if confidence >= 0.65:

            return "HIGH"

        if confidence >= 0.40:

            return "MEDIUM"

        if confidence > 0.0:

            return "LOW"

        return "NONE"

    def update(
        self,
        source_ip,
        anomaly_score
    ):

        score = float(
            anomaly_score
        )

        score = max(
            0.0,
            min(
                score,
                1.0
            )
        )

        state = self._classify_score(
            score
        )

        history = self.history[
            source_ip
        ]

        history.append(
            state
        )

        strong_streak = (
            self._calculate_streak(
                history
            )
        )

        strong_count = (
            self._calculate_strong_count(
                history
            )
        )

        very_strong_count = (
            self._calculate_very_strong_count(
                history
            )
        )

        persistence_ratio = (
            self._calculate_persistence_ratio(
                history
            )
        )

        persistent = (
            strong_streak
            >= self.persistence_threshold
        )

        very_strong_persistent = (

            very_strong_count
            >= self.persistence_threshold

        )

        temporal_confidence = (
            self._calculate_temporal_confidence(
                strong_streak,
                persistence_ratio,
                very_strong_count
            )
        )

        result = {

            "source_ip":
                source_ip,

            "current_score":
                round(
                    score,
                    4
                ),

            "current_state":
                state,

            "persistent":
                persistent,

            "very_strong_persistent":
                very_strong_persistent,

            "consecutive_anomalies":
                strong_streak,

            "strong_anomalies":
                strong_count,

            "very_strong_anomalies":
                very_strong_count,

            "history_length":
                len(history),

            "persistence_ratio":
                round(
                    persistence_ratio,
                    4
                ),

            "temporal_confidence":
                temporal_confidence,

            "history":
                list(history)

        }

        self.last_result[
            source_ip
        ] = result

        return result

    def get_source_state(
        self,
        source_ip
    ):

        if source_ip in self.last_result:

            return self.last_result[
                source_ip
            ]

        return {

            "source_ip":
                source_ip,

            "current_score":
                0.0,

            "current_state":
                "NORMAL",

            "persistent":
                False,

            "very_strong_persistent":
                False,

            "consecutive_anomalies":
                0,

            "strong_anomalies":
                0,

            "very_strong_anomalies":
                0,

            "history_length":
                0,

            "persistence_ratio":
                0.0,

            "temporal_confidence":
                "NONE",

            "history":
                []

        }

    def get_history(
        self,
        source_ip
    ):

        return list(
            self.history.get(
                source_ip,
                []
            )
        )

    def clear_source(
        self,
        source_ip
    ):

        if source_ip in self.history:

            del self.history[
                source_ip
            ]

        if source_ip in self.last_result:

            del self.last_result[
                source_ip
            ]

    def clear_all(self):

        self.history.clear()

        self.last_result.clear()


if __name__ == "__main__":

    detector = TemporalDetector(
        strong_threshold=0.60,
        very_strong_threshold=0.85,
        persistence_threshold=3,
        history_size=10
    )

    source = "192.168.1.100"

    test_scores = [

        0.20,

        0.35,

        0.55,

        0.20,

        0.75,

        0.82,

        0.91,

        0.30,

        0.70,

        0.95,

        0.97

    ]

    print("=" * 95)

    print(
        "                 AEGISNET TEMPORAL PERSISTENCE ENGINE"
    )

    print("=" * 95)

    print()

    print(
        "Threshold configuration:"
    )

    print(
        "  Strong threshold       : 0.60"
    )

    print(
        "  Very strong threshold  : 0.85"
    )

    print(
        "  Persistence threshold  : 3 consecutive strong anomalies"
    )

    print(
        "  History size           : 10 windows"
    )

    print()

    print(
        "TEMPORAL TEST"
    )

    print("-" * 95)

    for window, score in enumerate(
        test_scores,
        start=1
    ):

        result = detector.update(
            source,
            score
        )

        print()

        print(
            f"Window {window:02d}"
        )

        print(
            f"  ML score              : "
            f"{score:.2f}"
        )

        print(
            f"  Classification        : "
            f"{result['current_state']}"
        )

        print(
            f"  Strong streak         : "
            f"{result['consecutive_anomalies']}"
        )

        print(
            f"  Strong count          : "
            f"{result['strong_anomalies']}"
        )

        print(
            f"  Very strong count     : "
            f"{result['very_strong_anomalies']}"
        )

        print(
            f"  Persistence ratio     : "
            f"{result['persistence_ratio']:.2f}"
        )

        print(
            f"  Persistent            : "
            f"{result['persistent']}"
        )

        print(
            f"  Very-strong persistent: "
            f"{result['very_strong_persistent']}"
        )

        print(
            f"  Temporal confidence   : "
            f"{result['temporal_confidence']}"
        )

        print(
            f"  History               : "
            f"{result['history']}"
        )

    print()

    print("=" * 95)

    print(
        "TEST 1 — WEAK/MODERATE ANOMALIES"
    )

    print("-" * 95)

    detector.clear_all()

    weak_scores = [
        0.20,
        0.40,
        0.55,
        0.30,
        0.50
    ]

    for score in weak_scores:

        result = detector.update(
            source,
            score
        )

    print(
        f"Persistent            : "
        f"{result['persistent']}"
    )

    print(
        f"Strong streak         : "
        f"{result['consecutive_anomalies']}"
    )

    print(
        f"Temporal confidence   : "
        f"{result['temporal_confidence']}"
    )

    assert result[
        "persistent"
    ] is False

    print(
        "PASS — transient anomalies do not persist."
    )

    print()

    print("=" * 95)

    print(
        "TEST 2 — THREE CONSECUTIVE STRONG ANOMALIES"
    )

    print("-" * 95)

    detector.clear_all()

    strong_scores = [
        0.72,
        0.81,
        0.90
    ]

    for score in strong_scores:

        result = detector.update(
            source,
            score
        )

    print(
        f"Persistent            : "
        f"{result['persistent']}"
    )

    print(
        f"Strong streak         : "
        f"{result['consecutive_anomalies']}"
    )

    print(
        f"Persistence ratio     : "
        f"{result['persistence_ratio']:.2f}"
    )

    print(
        f"Temporal confidence   : "
        f"{result['temporal_confidence']}"
    )

    assert result[
        "persistent"
    ] is True

    assert result[
        "consecutive_anomalies"
    ] == 3

    print(
        "PASS — persistence confirmed after 3 strong windows."
    )

    print()

    print("=" * 95)

    print(
        "TEST 3 — STRONG ANOMALY BROKEN BY NORMAL WINDOW"
    )

    print("-" * 95)

    detector.clear_all()

    recovery_scores = [
        0.75,
        0.80,
        0.30,
        0.90
    ]

    for score in recovery_scores:

        result = detector.update(
            source,
            score
        )

    print(
        f"Persistent            : "
        f"{result['persistent']}"
    )

    print(
        f"Strong streak         : "
        f"{result['consecutive_anomalies']}"
    )

    print(
        f"History               : "
        f"{result['history']}"
    )

    assert result[
        "persistent"
    ] is False

    assert result[
        "consecutive_anomalies"
    ] == 1

    print(
        "PASS — normal window breaks persistence streak."
    )

    print()

    print("=" * 95)

    print(
        "TEST 4 — VERY STRONG PERSISTENCE"
    )

    print("-" * 95)

    detector.clear_all()

    very_strong_scores = [
        0.90,
        0.92,
        0.97,
        0.99
    ]

    for score in very_strong_scores:

        result = detector.update(
            source,
            score
        )

    print(
        f"Persistent            : "
        f"{result['persistent']}"
    )

    print(
        f"Very-strong persistent: "
        f"{result['very_strong_persistent']}"
    )

    print(
        f"Strong streak         : "
        f"{result['consecutive_anomalies']}"
    )

    print(
        f"Very strong count     : "
        f"{result['very_strong_anomalies']}"
    )

    print(
        f"Temporal confidence   : "
        f"{result['temporal_confidence']}"
    )

    assert result[
        "persistent"
    ] is True

    assert result[
        "very_strong_persistent"
    ] is True

    print(
        "PASS — sustained very-strong anomaly confirmed."
    )

    print()

    print("=" * 95)

    print(
        "All temporal persistence tests passed successfully."
    )

    print("=" * 95)