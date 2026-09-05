from dataclasses import dataclass
from typing import Dict, Any, List


@dataclass
class FusionWeights:
    rule: float = 0.25
    ml: float = 0.25
    baseline: float = 0.15
    temporal: float = 0.15
    port_scan: float = 0.10
    source_context: float = 0.10


class ThreatFusionEngine:

    LOW_THRESHOLD = 30.0
    MEDIUM_THRESHOLD = 50.0
    HIGH_THRESHOLD = 70.0
    CRITICAL_THRESHOLD = 85.0

    def __init__(self, weights: FusionWeights = None):
        self.weights = weights or FusionWeights()

    # =========================================================
    # RULE SCORE
    # =========================================================

    def calculate_rule_score(
        self,
        alerts: List[Dict[str, Any]]
    ) -> float:

        if not alerts:
            return 0.0

        severity_values = {
            "CRITICAL": 100.0,
            "HIGH": 80.0,
            "MEDIUM": 50.0,
            "LOW": 20.0
        }

        scores = []

        for alert in alerts:
            severity = str(
                alert.get("severity", "LOW")
            ).upper()

            scores.append(
                severity_values.get(
                    severity,
                    0.0
                )
            )

        return max(scores) if scores else 0.0

    # =========================================================
    # ML ANOMALY SCORE
    # =========================================================

    def calculate_ml_score(
        self,
        ml_anomaly: bool,
        ml_confidence: float,
        anomaly_strength: str
    ) -> float:

        if not ml_anomaly:
            return 0.0

        strength_multiplier = {
            "WEAK": 0.35,
            "MODERATE": 0.60,
            "STRONG": 0.85,
            "VERY_STRONG": 1.00
        }

        strength = str(
            anomaly_strength
        ).upper()

        multiplier = strength_multiplier.get(
            strength,
            0.0
        )

        confidence = max(
            0.0,
            min(
                float(ml_confidence),
                1.0
            )
        )

        return min(
            100.0,
            confidence * 100.0 * multiplier
        )

    # =========================================================
    # ADAPTIVE BASELINE SCORE
    # =========================================================

    def calculate_baseline_score(
        self,
        baseline_score: float
    ) -> float:

        baseline_score = max(
            0.0,
            min(
                float(baseline_score),
                1.0
            )
        )

        return baseline_score * 100.0

    # =========================================================
    # TEMPORAL PERSISTENCE SCORE
    # =========================================================

    def calculate_temporal_score(
        self,
        temporal_result: Dict[str, Any]
    ) -> float:

        if not temporal_result:
            return 0.0

        streak = int(
            temporal_result.get(
                "strong_streak",
                temporal_result.get(
                    "consecutive_anomalies",
                    0
                )
            )
        )

        very_strong_persistent = bool(
            temporal_result.get(
                "very_strong_persistent",
                False
            )
        )

        persistent = bool(
            temporal_result.get(
                "persistent",
                False
            )
        )

        if very_strong_persistent:
            return 100.0

        if streak >= 8:
            return 100.0

        if streak >= 6:
            return 90.0

        if streak >= 5:
            return 80.0

        if streak >= 4:
            return 70.0

        if streak >= 3 and persistent:
            return 60.0

        return 0.0

    # =========================================================
    # PORT SCAN SCORE
    # =========================================================

    def calculate_port_scan_score(
        self,
        port_scan_detected: bool
    ) -> float:

        if port_scan_detected:
            return 100.0

        return 0.0

    # =========================================================
    # SOURCE CONTEXT
    #
    # Source context is attribution, NOT independent proof
    # of malicious activity.
    # =========================================================

    def calculate_source_context(
        self,
        source_context: Dict[str, Any]
    ) -> Dict[str, float]:

        if not source_context:
            return {
                "attribution_score": 0.0,
                "behavior_modifier": 0.0
            }

        packet_share = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "packet_share",
                        0.0
                    )
                ),
                1.0
            )
        )

        byte_share = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "byte_share",
                        0.0
                    )
                ),
                1.0
            )
        )

        flow_share = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "flow_share",
                        0.0
                    )
                ),
                1.0
            )
        )

        activity_score = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "activity_score",
                        0.0
                    )
                ),
                1.0
            )
        )

        attribution = (
            packet_share * 0.40 +
            byte_share * 0.30 +
            flow_share * 0.15 +
            activity_score * 0.15
        )

        syn_ratio = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "syn_ratio",
                        0.0
                    )
                ),
                1.0
            )
        )

        rst_ratio = max(
            0.0,
            min(
                float(
                    source_context.get(
                        "rst_ratio",
                        0.0
                    )
                ),
                1.0
            )
        )

        behavior_modifier = 0.0

        if syn_ratio >= 0.50:
            behavior_modifier += 0.10
        elif syn_ratio >= 0.30:
            behavior_modifier += 0.05

        if rst_ratio >= 0.50:
            behavior_modifier += 0.10
        elif rst_ratio >= 0.30:
            behavior_modifier += 0.05

        return {
            "attribution_score": min(
                attribution * 100.0,
                100.0
            ),
            "behavior_modifier": behavior_modifier
        }

    # =========================================================
    # THREAT SEVERITY
    # =========================================================

    def determine_severity(
        self,
        score: float
    ) -> str:

        if score >= self.CRITICAL_THRESHOLD:
            return "CRITICAL"

        if score >= self.HIGH_THRESHOLD:
            return "HIGH"

        if score >= self.MEDIUM_THRESHOLD:
            return "MEDIUM"

        if score >= self.LOW_THRESHOLD:
            return "LOW"

        return "NORMAL"

    # =========================================================
    # CONFIDENCE
    # =========================================================

    def determine_confidence(
        self,
        evidence_count: int
    ) -> str:

        if evidence_count >= 4:
            return "VERY_HIGH"

        if evidence_count >= 3:
            return "HIGH"

        if evidence_count == 2:
            return "MEDIUM"

        if evidence_count == 1:
            return "LOW"

        return "NONE"

    # =========================================================
    # MAIN THREAT FUSION
    # =========================================================

    def fuse(
        self,
        rule_alerts: List[Dict[str, Any]] = None,
        ml_anomaly: bool = False,
        ml_confidence: float = 0.0,
        anomaly_strength: str = "NORMAL",
        baseline_score: float = 0.0,
        temporal_result: Dict[str, Any] = None,
        port_scan_detected: bool = False,
        source_context: Dict[str, Any] = None,
        existing_threat_score: float = 0.0
    ) -> Dict[str, Any]:

        rule_alerts = rule_alerts or []
        temporal_result = temporal_result or {}
        source_context = source_context or {}

        # -----------------------------------------------------
        # Calculate individual components
        # -----------------------------------------------------

        rule_score = self.calculate_rule_score(
            rule_alerts
        )

        ml_score = self.calculate_ml_score(
            ml_anomaly,
            ml_confidence,
            anomaly_strength
        )

        baseline_component = self.calculate_baseline_score(
            baseline_score
        )

        temporal_score = self.calculate_temporal_score(
            temporal_result
        )

        port_scan_score = self.calculate_port_scan_score(
            port_scan_detected
        )

        source_info = self.calculate_source_context(
            source_context
        )

        attribution_score = source_info[
            "attribution_score"
        ]

        behavior_modifier = source_info[
            "behavior_modifier"
        ]

        # -----------------------------------------------------
        # MALICIOUS EVIDENCE
        #
        # Only actual detection mechanisms count here.
        #
        # Source context is deliberately excluded.
        # Adaptive baseline is contextual and does not count
        # as malicious evidence by itself.
        # -----------------------------------------------------

        malicious_components = {
            "RULE": rule_score,
            "ML_ANOMALY": ml_score,
            "TEMPORAL_PERSISTENCE": temporal_score,
            "PORT_SCAN": port_scan_score
        }

        contextual_components = {
            "ADAPTIVE_BASELINE": baseline_component
        }

        # -----------------------------------------------------
        # Weighted threat score
        # -----------------------------------------------------

        weighted_score = (
            rule_score *
            self.weights.rule

            +

            ml_score *
            self.weights.ml

            +

            baseline_component *
            self.weights.baseline

            +

            temporal_score *
            self.weights.temporal

            +

            port_scan_score *
            self.weights.port_scan
        )

        # -----------------------------------------------------
        # Identify genuine malicious evidence
        # -----------------------------------------------------

        malicious_evidence = [
            name
            for name, value
            in malicious_components.items()
            if value >= 50.0
        ]

        contextual_anomalies = [
            name
            for name, value
            in contextual_components.items()
            if value >= 50.0
        ]

        evidence_count = len(
            malicious_evidence
        )

        # -----------------------------------------------------
        # Source attribution modifier
        #
        # Attribution has an effect ONLY when there is already
        # genuine malicious evidence.
        # -----------------------------------------------------

        context_boost = 0.0

        if evidence_count > 0:

            context_boost = (
                attribution_score *
                self.weights.source_context *
                0.35
            )

            context_boost *= (
                1.0 +
                behavior_modifier
            )

            weighted_score += context_boost

        # -----------------------------------------------------
        # Existing threat score stabilization
        # -----------------------------------------------------

        existing_score = max(
            0.0,
            min(
                float(existing_threat_score),
                100.0
            )
        )

        fusion_score = (
            weighted_score * 0.80
            +
            existing_score * 0.20
        )

        # -----------------------------------------------------
        # Multi-signal agreement bonus
        #
        # ONLY genuine malicious evidence participates.
        # -----------------------------------------------------

        agreement_bonus = min(
            evidence_count * 5.0,
            25.0
        )

        if evidence_count >= 2:
            fusion_score += agreement_bonus

        fusion_score = max(
            0.0,
            min(
                fusion_score,
                100.0
            )
        )

        # -----------------------------------------------------
        # Final classification
        # -----------------------------------------------------

        severity = self.determine_severity(
            fusion_score
        )

        confidence = self.determine_confidence(
            evidence_count
        )

        # -----------------------------------------------------
        # Source attribution classification
        # -----------------------------------------------------

        attribution_level = "LOW"

        if attribution_score >= 75.0:
            attribution_level = "VERY_HIGH"

        elif attribution_score >= 50.0:
            attribution_level = "HIGH"

        elif attribution_score >= 25.0:
            attribution_level = "MEDIUM"

        # -----------------------------------------------------
        # Final result
        # -----------------------------------------------------

        return {

            # Primary score
            "fusion_score": round(
                fusion_score,
                2
            ),

            # Backward compatibility
            "score": round(
                fusion_score,
                2
            ),

            "threat_score": round(
                fusion_score,
                2
            ),

            # Classification
            "severity": severity,

            "confidence": confidence,

            # Individual components
            "rule_score": round(
                rule_score,
                2
            ),

            "ml_score": round(
                ml_score,
                2
            ),

            "baseline_score": round(
                baseline_component,
                2
            ),

            "temporal_score": round(
                temporal_score,
                2
            ),

            "port_scan_score": round(
                port_scan_score,
                2
            ),

            # Source attribution
            "source_attribution_score": round(
                attribution_score,
                2
            ),

            "source_attribution_level":
                attribution_level,

            "behavior_modifier": round(
                behavior_modifier,
                3
            ),

            # Evidence
            "malicious_evidence_sources":
                malicious_evidence,

            "contextual_anomaly_sources":
                contextual_anomalies,

            "evidence_count":
                evidence_count,

            "agreement_bonus":
                round(
                    agreement_bonus,
                    2
                ),

            "context_boost":
                round(
                    context_boost,
                    2
                ),

            # Explicit architecture indicator
            "source_context_used_as_evidence":
                False,

            # ML information
            "ml_anomaly":
                bool(ml_anomaly),

            "ml_confidence":
                round(
                    float(ml_confidence),
                    4
                ),

            "anomaly_strength":
                anomaly_strength
        }


# =============================================================
# STANDALONE VALIDATION TESTS
# =============================================================

def run_tests():

    engine = ThreatFusionEngine()

    # =========================================================
    # TEST 1
    #
    # High-volume but benign source.
    #
    # Important:
    # High source attribution and baseline deviation must NOT
    # automatically become malicious evidence.
    # =========================================================

    result1 = engine.fuse(

        rule_alerts=[],

        ml_anomaly=False,

        ml_confidence=0.0,

        anomaly_strength="NORMAL",

        baseline_score=0.66,

        temporal_result={},

        port_scan_detected=False,

        source_context={
            "packet_share": 0.80,
            "byte_share": 0.93,
            "flow_share": 0.75,
            "activity_score": 0.76,
            "syn_ratio": 0.02,
            "rst_ratio": 0.01
        },

        existing_threat_score=20
    )

    print(
        "\nTEST 1 - BENIGN HIGH-VOLUME SOURCE"
    )

    print(result1)

    assert result1["severity"] == "NORMAL"

    assert (
        result1["malicious_evidence_sources"]
        == []
    )

    assert (
        result1["evidence_count"]
        == 0
    )

    assert (
        result1["source_context_used_as_evidence"]
        is False
    )

    assert (
        "ADAPTIVE_BASELINE"
        in result1[
            "contextual_anomaly_sources"
        ]
    )

    # =========================================================
    # TEST 2
    #
    # Single strong ML anomaly.
    #
    # It should be detected but remain conservative.
    # =========================================================

    result2 = engine.fuse(

        rule_alerts=[],

        ml_anomaly=True,

        ml_confidence=0.62,

        anomaly_strength="STRONG",

        baseline_score=0.20,

        temporal_result={
            "persistent": False,
            "consecutive_anomalies": 1
        },

        port_scan_detected=False,

        source_context={
            "packet_share": 0.20,
            "byte_share": 0.30,
            "flow_share": 0.15,
            "activity_score": 0.20
        },

        existing_threat_score=10
    )

    print(
        "\nTEST 2 - SINGLE ML ANOMALY"
    )

    print(result2)

    assert (
        "ML_ANOMALY"
        in result2[
            "malicious_evidence_sources"
        ]
    )

    assert (
        result2["evidence_count"]
        == 1
    )

    assert (
        result2["source_context_used_as_evidence"]
        is False
    )

    # =========================================================
    # TEST 3
    #
    # Multiple independent detection mechanisms agree.
    #
    # Expected:
    # CRITICAL
    # Very high confidence
    # Multiple malicious evidence sources
    # =========================================================

    result3 = engine.fuse(

        rule_alerts=[
            {
                "type": "SYN_FLOOD",
                "severity": "HIGH"
            }
        ],

        ml_anomaly=True,

        ml_confidence=0.95,

        anomaly_strength="VERY_STRONG",

        baseline_score=0.90,

        temporal_result={
            "persistent": True,
            "consecutive_anomalies": 5,
            "very_strong_persistent": True
        },

        port_scan_detected=True,

        source_context={
            "packet_share": 0.85,
            "byte_share": 0.90,
            "flow_share": 0.80,
            "activity_score": 0.85,
            "syn_ratio": 0.70,
            "rst_ratio": 0.60
        },

        existing_threat_score=85
    )

    print(
        "\nTEST 3 - MULTI-SIGNAL ATTACK"
    )

    print(result3)

    assert (
        result3["severity"]
        == "CRITICAL"
    )

    assert (
        result3["evidence_count"]
        >= 4
    )

    assert (
        "RULE"
        in result3[
            "malicious_evidence_sources"
        ]
    )

    assert (
        "ML_ANOMALY"
        in result3[
            "malicious_evidence_sources"
        ]
    )

    assert (
        "TEMPORAL_PERSISTENCE"
        in result3[
            "malicious_evidence_sources"
        ]
    )

    assert (
        "PORT_SCAN"
        in result3[
            "malicious_evidence_sources"
        ]
    )

    assert (
        result3["confidence"]
        == "VERY_HIGH"
    )

    assert (
        result3["source_context_used_as_evidence"]
        is False
    )

    # =========================================================
    # TEST 4
    #
    # Baseline anomaly + high source attribution, but no
    # malicious detection signal.
    #
    # This must remain non-malicious.
    # =========================================================

    result4 = engine.fuse(

        rule_alerts=[],

        ml_anomaly=False,

        ml_confidence=0.0,

        anomaly_strength="NORMAL",

        baseline_score=0.95,

        temporal_result={},

        port_scan_detected=False,

        source_context={
            "packet_share": 0.90,
            "byte_share": 0.95,
            "flow_share": 0.90,
            "activity_score": 0.90,
            "syn_ratio": 0.01,
            "rst_ratio": 0.01
        },

        existing_threat_score=15
    )

    print(
        "\nTEST 4 - BASELINE DEVIATION WITHOUT MALICIOUS SIGNAL"
    )

    print(result4)

    assert (
        result4["malicious_evidence_sources"]
        == []
    )

    assert (
        result4["evidence_count"]
        == 0
    )

    assert (
        result4["source_context_used_as_evidence"]
        is False
    )

    # =========================================================
    # FINAL
    # =========================================================

    print(
        "\nALL THREAT FUSION TESTS PASSED."
    )


if __name__ == "__main__":
    run_tests()