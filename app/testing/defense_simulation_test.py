from app.response.response_controller import ResponseController


def print_result(step, score, result):

    print()
    print("=" * 80)
    print(f"STEP {step}")
    print("=" * 80)

    print(f"Threat Score       : {score}")
    print(f"Previous State     : {result['previous_state']}")
    print(f"Current State      : {result['current_state']}")
    print(f"Action             : {result['action']}")
    print(f"Mode               : {result['mode']}")
    print(f"Previous Score     : {result['previous_score']}")
    print(f"Current Score      : {result['current_score']}")
    print(f"Effectiveness      : {result['effectiveness']}")
    print(f"Recommendation     : {result['recommendation']}")

    if result["improvement_ratio"] is not None:
        print(
            f"Improvement        : "
            f"{result['improvement_ratio'] * 100:.2f}%"
        )


def main():

    controller = ResponseController(
        simulation_mode=True
    )

    source_ip = "192.168.100.50"

    test_sequence = [
        (25, False),
        (45, True),
        (65, True),
        (85, True),
        (55, True),
        (35, False),
        (20, False)
    ]

    print()
    print("=" * 80)
    print("          AEGISNET CONTROLLED DEFENSE SIMULATION")
    print("=" * 80)

    for step, (score, anomaly) in enumerate(
        test_sequence,
        start=1
    ):

        result = controller.process(
            source_ip=source_ip,
            threat_score=score,
            ml_result={
                "is_anomaly": anomaly,
                "anomaly_score": score / 100,
                "ml_confidence": score / 100
            },
            alerts=[]
        )

        print_result(
            step,
            score,
            result
        )

    print()
    print("=" * 80)
    print("FINAL ACTIVE RESPONSES")
    print("=" * 80)

    active = controller.get_active_responses()

    if active:
        for ip, response in active.items():
            print(
                f"{ip} -> "
                f"{response['action']}"
            )
    else:
        print("No active defensive responses.")

    print()
    print("=" * 80)
    print("Defense simulation completed.")
    print("=" * 80)


if __name__ == "__main__":
    main()