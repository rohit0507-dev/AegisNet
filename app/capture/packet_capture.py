import traceback

from scapy.all import sniff, conf

from app.analysis.flow_engine import FlowEngine
from app.analysis.window_manager import WindowManager
from app.analysis.window_feature_engine import WindowFeatureEngine
from app.analysis.adaptive_baseline import AdaptiveBaseline
from app.analysis.source_context import SourceContextEngine

from app.detection.rule_engine import RuleEngine
from app.detection.port_scan_detector import PortScanDetector
from app.detection.temporal_detector import TemporalDetector

from app.scoring.threat_fusion import ThreatFusionEngine
from app.scoring.threat_scorer import ThreatScorer

from app.ml.anomaly_detector import AnomalyDetector

from app.response.response_controller import ResponseController

from app.database.database import Database


CAPTURE_INTERFACE_INDEX = 16
WINDOW_SECONDS = 5


class PacketCapture:

    def __init__(self):

        print("[INIT] Initializing AegisNet...")

        self.interface = conf.ifaces.dev_from_index(
            CAPTURE_INTERFACE_INDEX
        )

        print(
            f"[CAPTURE] Interface: {self.interface.name}"
        )

        self.flow_engine = FlowEngine()

        self.window_manager = WindowManager(
            window_seconds=WINDOW_SECONDS
        )

        self.window_feature_engine = WindowFeatureEngine()

        self.baseline = AdaptiveBaseline()

        self.source_context = SourceContextEngine()

        self.rule_engine = RuleEngine()

        self.port_scan_detector = PortScanDetector()

        self.temporal_detector = TemporalDetector()

        self.threat_fusion = ThreatFusionEngine()

        self.threat_scorer = ThreatScorer()

        self.ml_detector = AnomalyDetector()

        self.response_controller = ResponseController(
            simulation_mode=True
        )

        self.database = Database()

        self.packet_count = 0
        self.window_id = 0
        self.ml_model_loaded = False

        try:

            self.ml_detector.load_model()

            self.ml_model_loaded = True

            print(
                "[ML] Isolation Forest model loaded"
            )

        except Exception as e:

            print(
                f"[ML] Model loading failed: {e}"
            )

            print(
                "[ML] Continuing without ML model"
            )

    # =========================================================
    # PACKET PROCESSING
    # =========================================================

    def process_packet(self, packet):

        try:

            self.flow_engine.process_packet(packet)

            self.packet_count += 1

            if self.window_manager.is_expired():

                self.process_window()

                self.window_manager.reset()

        except Exception as e:

            print(
                f"[PACKET ERROR] {e}"
            )

    # =========================================================
    # TEMPORAL STRENGTH
    # =========================================================

    def _temporal_strength_value(self, result):

        state = result.get(
            "current_state",
            "NORMAL"
        )

        state_values = {
            "NORMAL": 0.00,
            "WEAK": 0.25,
            "STRONG": 0.60,
            "VERY_STRONG": 0.85
        }

        base_value = state_values.get(
            state,
            0.00
        )

        persistence_ratio = float(
            result.get(
                "persistence_ratio",
                0.00
            )
        )

        consecutive_anomalies = float(
            result.get(
                "consecutive_anomalies",
                0
            )
        )

        return (
            base_value
            + min(persistence_ratio, 1.0) * 0.10
            + min(consecutive_anomalies, 10.0) * 0.01
        )

    # =========================================================
    # SELECT STRONGEST TEMPORAL RESULT
    # =========================================================

    def _select_temporal(self, temporal_results):

        if not temporal_results:

            return None

        return max(
            temporal_results,
            key=self._temporal_strength_value
        )

    # =========================================================
    # NORMALIZE ML RESULT
    # =========================================================

    def _normalize_ml_result(self, result):

        if not isinstance(result, dict):

            return {
                "anomaly": False,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "anomaly_strength": "NORMAL"
            }

        anomaly_value = result.get(
            "is_anomaly",
            result.get(
                "anomaly",
                False
            )
        )

        return {
            "anomaly": bool(anomaly_value),
            "is_anomaly": bool(anomaly_value),
            "anomaly_score": float(
                result.get(
                    "anomaly_score",
                    0.0
                )
            ),
            "confidence": float(
                result.get(
                    "confidence",
                    0.0
                )
            ),
            "anomaly_strength": result.get(
                "anomaly_strength",
                "NORMAL"
            )
        }

    # =========================================================
    # ML PROCESSING - PER FLOW
    # =========================================================

    def _run_ml_per_flow(self, flow_features):

        results = []

        for features in flow_features:

            result = {
                "anomaly": False,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "anomaly_strength": "NORMAL"
            }

            if self.ml_model_loaded:

                try:

                    prediction = (
                        self.ml_detector.predict(
                            features
                        )
                    )

                    result = self._normalize_ml_result(
                        prediction
                    )

                except Exception as e:

                    print(
                        f"[ML FLOW ERROR] "
                        f"{features.get('source_ip', 'UNKNOWN')} "
                        f"{e}"
                    )

            results.append(result)

        return results

    # =========================================================
    # AGGREGATE ML RESULT FOR WINDOW FUSION
    # =========================================================

    def _aggregate_ml_results(self, ml_results):

        if not ml_results:

            return {
                "anomaly": False,
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "anomaly_strength": "NORMAL"
            }

        strongest = max(
            ml_results,
            key=lambda result: (
                result["confidence"],
                result["anomaly_score"]
            )
        )

        return {
            "anomaly": any(
                result["is_anomaly"]
                for result in ml_results
            ),

            "is_anomaly": any(
                result["is_anomaly"]
                for result in ml_results
            ),

            "anomaly_score": max(
                result["anomaly_score"]
                for result in ml_results
            ),

            "confidence": max(
                result["confidence"]
                for result in ml_results
            ),

            "anomaly_strength": strongest[
                "anomaly_strength"
            ]
        }

    # =========================================================
    # RAW FLOW EXTRACTION
    # =========================================================

    def _get_raw_flows(self):

        raw_flows = []

        for flow_group in self.flow_engine.flows.values():

            if isinstance(flow_group, dict):

                raw_flows.extend(
                    flow_group.values()
                )

            else:

                raw_flows.append(
                    flow_group
                )

        return raw_flows

    # =========================================================
    # FLOW IDENTITY
    # =========================================================

    def _flow_identity(self, flow):

        if isinstance(flow, dict):

            return (
                flow.get("source_ip"),
                flow.get("destination_ip"),
                flow.get("source_port"),
                flow.get("destination_port"),
                flow.get("protocol")
            )

        return (
            getattr(flow, "source_ip", None),
            getattr(flow, "destination_ip", None),
            getattr(flow, "source_port", None),
            getattr(flow, "destination_port", None),
            getattr(flow, "protocol", None)
        )

    # =========================================================
    # WINDOW PROCESSING
    # =========================================================

    def process_window(self):

        self.window_id += 1

        print()
        print("=" * 70)

        print(
            f"[WINDOW] Processing window "
            f"{self.window_id}"
        )

        try:

            # -------------------------------------------------
            # FLOW FEATURES
            # -------------------------------------------------

            flow_features = (
                self.flow_engine.get_all_features()
            )

            if not flow_features:

                print(
                    "[WINDOW] No flows detected"
                )

                return

            # -------------------------------------------------
            # RAW FLOWS
            # -------------------------------------------------

            raw_flows = self._get_raw_flows()

            if not raw_flows:

                print(
                    "[WINDOW] No raw flows detected"
                )

                return

            # -------------------------------------------------
            # WINDOW FEATURES
            # -------------------------------------------------

            window_features = (
                self.window_feature_engine.calculate(
                    flow_features
                )
            )

            print(
                f"[WINDOW] Flows: "
                f"{len(flow_features)}"
            )

            print(
                f"[WINDOW] Packets: "
                f"{window_features.get('total_packets', 0)}"
            )

            print(
                f"[WINDOW] Bytes: "
                f"{window_features.get('total_bytes', 0)}"
            )

            # -------------------------------------------------
            # ADAPTIVE BASELINE
            # -------------------------------------------------

            self.baseline.update(
                window_features
            )

            baseline_score = float(
                self.baseline.calculate_baseline_score(
                    window_features
                )
            )

            # -------------------------------------------------
            # PER-FLOW RULE DETECTION
            # -------------------------------------------------

            flow_rule_alerts = {}

            total_rule_alerts = 0

            for flow in raw_flows:

                identity = self._flow_identity(flow)

                alerts = []

                try:

                    detected = (
                        self.rule_engine.detect(
                            flow
                        )
                    )

                    if detected:

                        alerts.extend(
                            detected
                        )

                except Exception as e:

                    print(
                        f"[RULE ERROR] "
                        f"{e}"
                    )

                flow_rule_alerts[identity] = alerts

                total_rule_alerts += len(alerts)

            print(
                f"[RULES] Alerts: "
                f"{total_rule_alerts}"
            )

            # -------------------------------------------------
            # PORT SCAN DETECTION
            # -------------------------------------------------

            port_scan_detections = (
                self.port_scan_detector.detect(
                    flow_features
                )
            )

            if port_scan_detections is None:

                port_scan_detections = []

            port_scan_sources = set()

            for detection in port_scan_detections:

                source_ip = detection.get(
                    "source_ip"
                )

                if source_ip:

                    port_scan_sources.add(
                        source_ip
                    )

            port_scan_detected = bool(
                port_scan_detections
            )

            if port_scan_detected:

                print(
                    "[DETECTION] Port scan detected: "
                    f"{len(port_scan_detections)}"
                )

            # -------------------------------------------------
            # SOURCE CONTEXT
            # -------------------------------------------------

            contexts = (
                self.source_context.calculate(
                    flow_features,
                    window_features
                )
            )

            ranked_sources = (
                self.source_context.rank_sources(
                    contexts
                )
            )

            top_source_context = None

            if ranked_sources:

                top_source_context = (
                    ranked_sources[0]
                )

            # -------------------------------------------------
            # PER-FLOW ML DETECTION
            # -------------------------------------------------

            ml_results = self._run_ml_per_flow(
                flow_features
            )

            ml_by_identity = {}

            for features, ml_result in zip(
                flow_features,
                ml_results
            ):

                identity = self._flow_identity(
                    features
                )

                ml_by_identity[identity] = (
                    ml_result
                )

            # -------------------------------------------------
            # WINDOW ML AGGREGATION
            # -------------------------------------------------

            ml_result = self._aggregate_ml_results(
                ml_results
            )

            print(
                "[ML] "
                f"Anomalies="
                f"{sum(result['is_anomaly'] for result in ml_results)} "
                f"/ {len(ml_results)} "
                f"Score={ml_result['anomaly_score']:.4f} "
                f"Confidence={ml_result['confidence']:.4f} "
                f"Strength={ml_result['anomaly_strength']}"
            )

            # -------------------------------------------------
            # TEMPORAL ANALYSIS
            #
            # Temporal persistence is maintained separately
            # for every source IP.
            #
            # The temporal score is based on the strongest
            # ML confidence among anomalous flows belonging
            # to that source in the current window.
            # -------------------------------------------------

            temporal_results = []

            temporal_by_source = {}

            source_ips = set()

            for flow in flow_features:

                source_ip = flow.get(
                    "source_ip"
                )

                if source_ip:

                    source_ips.add(
                        source_ip
                    )

            for source_ip in source_ips:

                try:

                    source_ml_scores = []

                    for (
                        features,
                        ml_result_for_flow
                    ) in zip(
                        flow_features,
                        ml_results
                    ):

                        if features.get(
                            "source_ip"
                        ) != source_ip:

                            continue

                        is_anomaly = bool(
                            ml_result_for_flow.get(
                                "is_anomaly",
                                ml_result_for_flow.get(
                                    "anomaly",
                                    False
                                )
                            )
                        )

                        confidence = float(
                            ml_result_for_flow.get(
                                "confidence",
                                0.0
                            )
                        )

                        confidence = max(
                            0.0,
                            min(
                                confidence,
                                1.0
                            )
                        )

                        if is_anomaly:

                            source_ml_scores.append(
                                confidence
                            )

                    source_score = max(
                        source_ml_scores
                    ) if source_ml_scores else 0.0

                    temporal_result = (
                        self.temporal_detector.update(
                            source_ip,
                            source_score
                        )
                    )

                    if temporal_result:

                        temporal_results.append(
                            temporal_result
                        )

                        temporal_by_source[
                            source_ip
                        ] = temporal_result

                except Exception as e:

                    print(
                        f"[TEMPORAL ERROR] "
                        f"{e}"
                    )

            # -------------------------------------------------
            # SELECT STRONGEST TEMPORAL RESULT
            # FOR WINDOW-LEVEL FUSION
            # -------------------------------------------------

            selected_temporal = (
                self._select_temporal(
                    temporal_results
                )
            )

            if selected_temporal:

                print(
                    "[TEMPORAL] "
                    f"Source="
                    f"{selected_temporal.get('source_ip')} "
                    f"State="
                    f"{selected_temporal.get('current_state')} "
                    f"Streak="
                    f"{selected_temporal.get('consecutive_anomalies')} "
                    f"Persistence="
                    f"{selected_temporal.get('persistence_ratio')}"
                )

            # -------------------------------------------------
            # WINDOW THREAT FUSION
            # -------------------------------------------------

            fusion_result = (
                self.threat_fusion.fuse(

                    rule_alerts=[
                        alert
                        for alerts in flow_rule_alerts.values()
                        for alert in alerts
                    ],

                    ml_anomaly=
                        ml_result["is_anomaly"],

                    ml_confidence=
                        ml_result["confidence"],

                    anomaly_strength=
                        ml_result["anomaly_strength"],

                    baseline_score=
                        baseline_score,

                    temporal_result=
                        selected_temporal,

                    port_scan_detected=
                        port_scan_detected,

                    source_context=
                        top_source_context,

                    existing_threat_score=
                        0.0
                )
            )

            fusion_score = float(
                fusion_result.get(
                    "fusion_score",
                    fusion_result.get(
                        "score",
                        0.0
                    )
                )
            )

            print(
                "[FUSION] "
                f"Score={fusion_score:.2f} "
                f"Severity="
                f"{fusion_result.get('severity', 'NORMAL')} "
                f"Confidence="
                f"{fusion_result.get('confidence', 'NONE')}"
            )

            evidence = fusion_result.get(
                "malicious_evidence_sources",
                []
            )

            if evidence:

                print(
                    "[FUSION] Evidence: "
                    f"{', '.join(evidence)}"
                )

            contextual_sources = fusion_result.get(
                "contextual_anomaly_sources",
                []
            )

            if contextual_sources:

                print(
                    "[FUSION] Context: "
                    f"{', '.join(contextual_sources)}"
                )

            # -------------------------------------------------
            # PER-FLOW THREAT SCORING
            # -------------------------------------------------

            flow_threat_results = {}

            strongest_flow_threat = None

            for flow in raw_flows:

                identity = self._flow_identity(flow)

                alerts = list(
                    flow_rule_alerts.get(
                        identity,
                        []
                    )
                )

                source_ip = getattr(
                    flow,
                    "source_ip",
                    None
                )

                # ---------------------------------------------
                # ATTRIBUTE PORT SCAN ONLY TO ITS SOURCE
                # ---------------------------------------------

                if source_ip in port_scan_sources:

                    alerts.append({

                        "type": "PORT_SCAN",

                        "severity": "HIGH",

                        "message":
                            "Source associated with detected port scan."

                    })

                flow_ml_result = (
                    ml_by_identity.get(
                        identity,
                        {
                            "anomaly": False,
                            "is_anomaly": False,
                            "anomaly_score": 0.0,
                            "confidence": 0.0,
                            "anomaly_strength": "NORMAL"
                        }
                    )
                )

                try:

                    flow_threat = (
                        self.threat_scorer.calculate(
                            flow,
                            alerts,
                            flow_ml_result
                        )
                    )

                    if not isinstance(
                        flow_threat,
                        dict
                    ):

                        flow_threat = {
                            "score": 0.0,
                            "severity": "LOW",
                            "reasons": []
                        }

                except Exception as e:

                    print(
                        f"[THREAT SCORER ERROR] "
                        f"{e}"
                    )

                    flow_threat = {
                        "score": 0.0,
                        "severity": "LOW",
                        "reasons": []
                    }

                # ---------------------------------------------
                # KEEP FLOW SCORE AND SEVERITY TOGETHER
                # ---------------------------------------------

                flow_threat["score"] = float(
                    flow_threat.get(
                        "score",
                        0.0
                    )
                )

                flow_threat_results[identity] = {
                    "threat": flow_threat,
                    "alerts": alerts,
                    "ml_result": flow_ml_result
                }

                if (
                    strongest_flow_threat is None
                    or
                    flow_threat["score"]
                    >
                    strongest_flow_threat["score"]
                ):

                    strongest_flow_threat = {
                        "score":
                            flow_threat["score"],

                        "severity":
                            flow_threat.get(
                                "severity",
                                "LOW"
                            )
                    }

            # -------------------------------------------------
            # RESPONSE CONTROLLER
            #
            # IMPORTANT:
            # Defense operates on WINDOW-LEVEL fusion.
            # -------------------------------------------------

            source_ip = "GLOBAL"

            if top_source_context:

                source_ip = top_source_context.get(
                    "source_ip",
                    "GLOBAL"
                )

            response_result = (
                self.response_controller.process(

                    source_ip,

                    fusion_score,

                    ml_result=ml_result,

                    alerts=[
                        alert
                        for alerts in flow_rule_alerts.values()
                        for alert in alerts
                    ]
                )
            )

            if not isinstance(
                response_result,
                dict
            ):

                response_result = {}

            # -------------------------------------------------
            # RESPONSE FIELDS
            # -------------------------------------------------

            response_state = response_result.get(
                "state",
                "NORMAL"
            )

            response_action = response_result.get(
                "action"
            )

            if isinstance(
                response_state,
                dict
            ):

                response_state = response_state.get(
                    "state",
                    response_state.get(
                        "current_state",
                        "NORMAL"
                    )
                )

            response_mode = response_result.get(
                "mode",
                "SIMULATION"
            )

            effectiveness = response_result.get(
                "effectiveness"
            )

            recommendation = response_result.get(
                "recommendation"
            )

            previous_state = response_result.get(
                "previous_state"
            )

            previous_score = response_result.get(
                "previous_score"
            )

            current_score = response_result.get(
                "current_score",
                fusion_score
            )

            improvement_ratio = response_result.get(
                "improvement_ratio"
            )

            event_type = response_result.get(
                "event_type",
                "RESPONSE"
            )

            print(
                "[DEFENSE] "
                f"State={response_state} "
                f"Action={response_action} "
                f"Mode={response_mode}"
            )

            # -------------------------------------------------
            # DATABASE FLOW RECORDS
            #
            # Every flow receives:
            #
            #   - its own alerts
            #   - its own ML result
            #   - its own threat score
            #   - matching threat severity
            #   - temporal state belonging to its source
            #
            # Window fusion remains available through the
            # response event / window-level processing.
            # -------------------------------------------------

            for feature in flow_features:

                identity = self._flow_identity(
                    feature
                )

                flow_data = flow_threat_results.get(
                    identity
                )

                if flow_data is None:

                    flow_threat = {
                        "score": 0.0,
                        "severity": "LOW",
                        "reasons": []
                    }

                    flow_alerts = []

                    flow_ml_result = {
                        "anomaly": False,
                        "is_anomaly": False,
                        "anomaly_score": 0.0,
                        "confidence": 0.0,
                        "anomaly_strength": "NORMAL"
                    }

                else:

                    flow_threat = flow_data[
                        "threat"
                    ]

                    flow_alerts = flow_data[
                        "alerts"
                    ]

                    flow_ml_result = flow_data[
                        "ml_result"
                    ]

                # ---------------------------------------------
                # SOURCE-SPECIFIC TEMPORAL RESULT
                # ---------------------------------------------

                feature_source_ip = feature.get(
                    "source_ip"
                )

                temporal_result_for_flow = (
                    temporal_by_source.get(
                        feature_source_ip,
                        {
                            "current_state": "NORMAL",
                            "consecutive_anomalies": 0,
                            "persistence_ratio": 0.0,
                            "temporal_confidence": "NONE",
                            "persistent": False,
                            "very_strong_persistent": False
                        }
                    )
                )

                # ---------------------------------------------
                # DATABASE INSERTION
                # ---------------------------------------------

                try:

                    self.database.insert_flow(

                        feature,

                        flow_threat,

                        flow_alerts,

                        window_id=
                            self.window_id,

                        ml_result=
                            flow_ml_result,

                        response_result=
                            response_result,

                        temporal_result=
                            temporal_result_for_flow

                    )

                except Exception as e:

                    print(
                        f"[DATABASE FLOW ERROR] "
                        f"{e}"
                    )

            # -------------------------------------------------
            # DATABASE RESPONSE EVENT
            # -------------------------------------------------

            if response_result:

                try:

                    self.database.insert_response_event(

                        source_ip,

                        fusion_score,

                        response_state,

                        response_action,

                        response_mode,

                        previous_state=
                            previous_state,

                        effectiveness=
                            effectiveness,

                        recommendation=
                            recommendation,

                        previous_score=
                            previous_score,

                        current_score=
                            current_score,

                        improvement_ratio=
                            improvement_ratio,

                        event_type=
                            event_type

                    )

                except Exception as e:

                    print(
                        f"[RESPONSE DB ERROR] "
                        f"{e}"
                    )

            # -------------------------------------------------
            # WINDOW SUMMARY
            # -------------------------------------------------

            print(
                f"[WINDOW] Completed window "
                f"{self.window_id}"
            )

            print(
                f"[WINDOW] Fusion threat score: "
                f"{fusion_score:.2f}"
            )

            print(
                f"[WINDOW] Rule alerts: "
                f"{total_rule_alerts}"
            )

            print(
                f"[WINDOW] ML anomalies: "
                f"{sum(result['is_anomaly'] for result in ml_results)}"
            )

            if strongest_flow_threat:

                print(
                    f"[WINDOW] Strongest flow score: "
                    f"{strongest_flow_threat['score']:.2f} "
                    f"Severity="
                    f"{strongest_flow_threat['severity']}"
                )

        except Exception as e:

            print(
                f"[WINDOW ERROR] "
                f"{type(e).__name__}: {e}"
            )

            traceback.print_exc()

        finally:

            self.flow_engine.reset()

    # =========================================================
    # START CAPTURE
    # =========================================================

    def start(self):

        print()
        print("=" * 70)

        print(
            "AegisNet Network Traffic "
            "Monitoring Started"
        )

        print(
            "Defense Mode: SIMULATION"
        )

        print(
            f"Capture Interface: "
            f"{self.interface.name}"
        )

        print(
            f"Window Size: "
            f"{WINDOW_SECONDS} seconds"
        )

        print("=" * 70)

        print(
            "Generate normal traffic "
            "on this machine to test."
        )

        print(
            "Press CTRL+C to stop."
        )

        print()

        try:

            sniff(

                iface=self.interface,

                prn=self.process_packet,

                store=False

            )

        except KeyboardInterrupt:

            print()
            print(
                "[CAPTURE] Stopped by user."
            )

        except Exception as e:

            print(
                f"[CAPTURE ERROR] {e}"
            )

            traceback.print_exc()


def main():

    capture = PacketCapture()

    capture.start()


if __name__ == "__main__":

    main()