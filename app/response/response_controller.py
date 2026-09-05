from app.response.threat_state import ThreatStateEngine
from app.response.defense_decision import DefenseDecisionEngine
from app.response.response_manager import ResponseManager
from app.response.response_monitor import ResponseMonitor
from app.response.response_policy import ResponsePolicy


class ResponseController:

    def __init__(self, simulation_mode=True):

        self.simulation_mode = simulation_mode

        self.state_engines = {}

        self.decision_engine = DefenseDecisionEngine(
            simulation_mode=simulation_mode
        )

        self.response_policy = ResponsePolicy()

        self.response_manager = ResponseManager(
            simulation_mode=simulation_mode
        )

        self.response_monitor = ResponseMonitor()

        self.previous_scores = {}
        self.previous_actions = {}
        self.previous_effectiveness = {}

    def get_state_engine(self, source_ip):

        if source_ip not in self.state_engines:
            self.state_engines[source_ip] = ThreatStateEngine()

        return self.state_engines[source_ip]

    def _build_result(
        self,
        source_ip,
        state_result,
        decision,
        monitor_result,
        policy_result=None,
        restored=None,
        previous_score=None
    ):

        current_state = state_result.get(
            "current_state",
            state_result.get("state", "NORMAL")
        )

        previous_state = state_result.get(
            "previous_state"
        )

        action = decision.get(
            "action",
            "MONITOR"
        )

        mode = (
            "SIMULATION"
            if self.simulation_mode
            else "ACTIVE"
        )

        current_score = decision.get(
            "threat_score"
        )

        improvement_ratio = None
        effectiveness = None
        recommendation = None

        if monitor_result is not None:

            previous_score = monitor_result.get(
                "previous_score",
                previous_score
            )

            current_score = monitor_result.get(
                "current_score",
                current_score
            )

            improvement_ratio = monitor_result.get(
                "improvement_ratio"
            )

            effectiveness = monitor_result.get(
                "effectiveness"
            )

            recommendation = monitor_result.get(
                "recommendation"
            )

        return {
            "source_ip": source_ip,

            "state": state_result,

            "decision": decision,

            "monitor": monitor_result,

            "policy": policy_result,

            "restored": restored,

            "previous_state": previous_state,

            "current_state": current_state,

            "state_name": current_state,

            "action": action,

            "mode": mode,

            "effectiveness": effectiveness,

            "recommendation": recommendation,

            "previous_score": previous_score,

            "current_score": current_score,

            "improvement_ratio": improvement_ratio
        }

    def process(
        self,
        source_ip,
        threat_score,
        ml_result=None,
        alerts=None
    ):

        if ml_result is None:

            ml_result = {
                "is_anomaly": False,
                "anomaly_score": 0,
                "ml_confidence": 0
            }

        if alerts is None:
            alerts = []

        state_engine = self.get_state_engine(
            source_ip
        )

        state_result = state_engine.evaluate(
            threat_score
        )

        current_state = state_result.get(
            "current_state",
            "NORMAL"
        )

        previous_score = self.previous_scores.get(
            source_ip
        )

        previous_action = self.previous_actions.get(
            source_ip
        )

        previous_effectiveness = (
            self.previous_effectiveness.get(
                source_ip
            )
        )

        active_responses = (
            self.response_manager
            .get_active_responses()
        )

        active_response = active_responses.get(
            source_ip
        )

        monitor_result = None

        # --------------------------------------------------
        # MONITOR EXISTING RESPONSE
        # --------------------------------------------------

        if active_response is not None:

            if previous_score is not None:

                monitor_result = (
                    self.response_monitor.evaluate(
                        source_ip=source_ip,
                        previous_score=previous_score,
                        current_score=threat_score,
                        action=active_response["action"]
                    )
                )

                self.previous_effectiveness[
                    source_ip
                ] = monitor_result["effectiveness"]

        # --------------------------------------------------
        # RECOVERY
        # --------------------------------------------------

        if (
            current_state == "NORMAL"
            and active_response is not None
        ):

            restored_response = (
                self.response_manager.restore(
                    source_ip
                )
            )

            decision = {
                "action": "MONITOR",
                "threat_score": threat_score,
                "reasons": [
                    "Threat returned to normal range",
                    "Previous defensive response restored"
                ],
                "mode": (
                    "SIMULATION"
                    if self.simulation_mode
                    else "ACTIVE"
                )
            }

            policy_result = {
                "action": "MONITOR",
                "reasons": [
                    "Recovery detected"
                ]
            }

            self.previous_actions.pop(
                source_ip,
                None
            )

            self.previous_effectiveness.pop(
                source_ip,
                None
            )

            self.previous_scores[
                source_ip
            ] = threat_score

            return self._build_result(
                source_ip=source_ip,
                state_result=state_result,
                decision=decision,
                monitor_result=monitor_result,
                policy_result=policy_result,
                restored=restored_response,
                previous_score=previous_score
            )

        # --------------------------------------------------
        # NORMAL
        # --------------------------------------------------

        if current_state == "NORMAL":

            decision = {
                "action": "MONITOR",
                "threat_score": threat_score,
                "reasons": [
                    "Threat level is normal"
                ],
                "mode": (
                    "SIMULATION"
                    if self.simulation_mode
                    else "ACTIVE"
                )
            }

            policy_result = {
                "action": "MONITOR",
                "reasons": [
                    "Threat level is normal"
                ]
            }

            self.previous_scores[
                source_ip
            ] = threat_score

            self.previous_actions.pop(
                source_ip,
                None
            )

            self.previous_effectiveness.pop(
                source_ip,
                None
            )

            return self._build_result(
                source_ip=source_ip,
                state_result=state_result,
                decision=decision,
                monitor_result=monitor_result,
                policy_result=policy_result,
                previous_score=previous_score
            )

        # --------------------------------------------------
        # SELECT POLICY
        # --------------------------------------------------

        policy_result = (
            self.response_policy.select_action(
                state=current_state,
                threat_score=threat_score,
                ml_anomaly=ml_result.get(
                    "is_anomaly",
                    False
                ),
                alert_count=len(alerts),
                previous_action=previous_action,
                previous_effectiveness=previous_effectiveness
            )
        )

        # --------------------------------------------------
        # DEFENSE DECISION
        # --------------------------------------------------

        decision = (
            self.decision_engine.decide(
                state_result,
                ml_result,
                alerts
            )
        )

        decision["action"] = (
            policy_result["action"]
        )

        decision["reasons"] = (
            policy_result["reasons"]
        )

        decision["mode"] = (
            "SIMULATION"
            if self.simulation_mode
            else "ACTIVE"
        )

        decision["threat_score"] = threat_score

        # --------------------------------------------------
        # FEEDBACK CONTROL
        # --------------------------------------------------

        if active_response is not None:

            if monitor_result is not None:

                effectiveness = (
                    monitor_result[
                        "effectiveness"
                    ]
                )

                recommendation = (
                    monitor_result[
                        "recommendation"
                    ]
                )

                # ------------------------------------------
                # INEFFECTIVE RESPONSE
                # ------------------------------------------

                if recommendation == "ESCALATE":

                    escalation_policy = (
                        self.response_policy
                        .select_action(
                            state=current_state,
                            threat_score=threat_score,
                            ml_anomaly=ml_result.get(
                                "is_anomaly",
                                False
                            ),
                            alert_count=len(alerts),
                            previous_action=(
                                active_response[
                                    "action"
                                ]
                            ),
                            previous_effectiveness=(
                                "INEFFECTIVE"
                            )
                        )
                    )

                    decision["action"] = (
                        escalation_policy[
                            "action"
                        ]
                    )

                    decision["reasons"] = (
                        escalation_policy[
                            "reasons"
                        ]
                    )

                    self.response_manager.restore(
                        source_ip
                    )

                    self.response_manager.execute(
                        source_ip,
                        decision
                    )

                    self.previous_actions[
                        source_ip
                    ] = decision["action"]

                # ------------------------------------------
                # PARTIALLY EFFECTIVE
                # ------------------------------------------

                elif (
                    effectiveness
                    == "PARTIALLY_EFFECTIVE"
                ):

                    decision["action"] = (
                        active_response[
                            "action"
                        ]
                    )

                    decision["reasons"] = [
                        "Previous response partially effective",
                        "Maintaining current defensive action"
                    ]

                # ------------------------------------------
                # EFFECTIVE
                # ------------------------------------------

                elif effectiveness == "EFFECTIVE":

                    self.response_manager.restore(
                        source_ip
                    )

                    self.previous_actions.pop(
                        source_ip,
                        None
                    )

                    self.previous_effectiveness.pop(
                        source_ip,
                        None
                    )

                    decision["action"] = (
                        "MONITOR"
                    )

        # --------------------------------------------------
        # CREATE NEW RESPONSE
        # --------------------------------------------------

        active_responses = (
            self.response_manager
            .get_active_responses()
        )

        active_response = active_responses.get(
            source_ip
        )

        if (
            active_response is None
            and decision["action"] in [
                "TEMPORARY_LIMIT",
                "TEMPORARY_BLOCK",
                "QUARANTINE"
            ]
        ):

            self.response_manager.execute(
                source_ip,
                decision
            )

            self.previous_actions[
                source_ip
            ] = decision["action"]

        # --------------------------------------------------
        # SAVE CURRENT SCORE
        # --------------------------------------------------

        self.previous_scores[
            source_ip
        ] = threat_score

        # --------------------------------------------------
        # RETURN COMPLETE RESPONSE RESULT
        # --------------------------------------------------

        return self._build_result(
            source_ip=source_ip,
            state_result=state_result,
            decision=decision,
            monitor_result=monitor_result,
            policy_result=policy_result,
            previous_score=previous_score
        )

    def get_active_responses(self):

        return (
            self.response_manager
            .get_active_responses()
        )


if __name__ == "__main__":

    controller = ResponseController(
        simulation_mode=True
    )

    print("=" * 70)
    print("        AEGISNET RESPONSE CONTROLLER TEST")
    print("=" * 70)

    test_scores = [
        25,
        45,
        65,
        85,
        55,
        35,
        20
    ]

    source_ip = "192.168.100.50"

    for score in test_scores:

        result = controller.process(
            source_ip=source_ip,
            threat_score=score,
            ml_result={
                "is_anomaly": score >= 45,
                "anomaly_score": score / 100,
                "ml_confidence": score / 100
            },
            alerts=[]
        )

        print()
        print(
            f"Threat Score       : {score}"
        )

        print(
            f"Previous State     : "
            f"{result['previous_state']}"
        )

        print(
            f"Current State      : "
            f"{result['current_state']}"
        )

        print(
            f"Action             : "
            f"{result['action']}"
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
            f"Effectiveness      : "
            f"{result['effectiveness']}"
        )

        print(
            f"Recommendation     : "
            f"{result['recommendation']}"
        )

        if result["improvement_ratio"] is not None:

            print(
                f"Improvement        : "
                f"{result['improvement_ratio'] * 100:.2f}%"
            )

    print()
    print("=" * 70)
    print("Response controller test completed.")
    print("=" * 70)