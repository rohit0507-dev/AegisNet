import os
import json

from app.response.response_controller import ResponseController


BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "evaluation"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


def run_scenario(
    controller,
    source_ip,
    scores
):

    results = []

    for score in scores:

        result = controller.process(
            source_ip,
            score
        )

        results.append({
            "score": score,
            "result": result
        })

    return results


def summarize_scenario(
    name,
    results
):

    actions = []
    states = []
    effectiveness = []
    recommendations = []

    for item in results:

        result = item["result"]

        actions.append(
            result.get(
                "action"
            )
        )

        state = result.get(
            "state",
            result.get(
                "current_state",
                "UNKNOWN"
            )
        )

        if isinstance(
            state,
            dict
        ):

            state = state.get(
                "state",
                state.get(
                    "current_state",
                    "UNKNOWN"
                )
            )

        states.append(
            state
        )

        effectiveness.append(
            result.get(
                "effectiveness"
            )
        )

        recommendations.append(
            result.get(
                "recommendation"
            )
        )

    return {
        "scenario": name,
        "scores": [
            item["score"]
            for item in results
        ],
        "states": states,
        "actions": actions,
        "effectiveness": effectiveness,
        "recommendations": recommendations
    }


def main():

    print("=" * 90)

    print(
        "              AEGISNET END-TO-END DEFENSE EVALUATION"
    )

    print("=" * 90)

    print()

    print(
        "Defense mode: SIMULATION"
    )

    print(
        "No real network blocking is performed."
    )

    print()

    scenarios = {

        "NORMAL_RECOVERY": [
            20,
            25,
            30,
            20
        ],

        "GRADUAL_ESCALATION": [
            20,
            45,
            65,
            85
        ],

        "EFFECTIVE_RECOVERY": [
            85,
            55,
            35,
            20
        ],

        "FAILED_BLOCK_ESCALATION": [
            85,
            90
        ],

        "PARTIAL_IMPROVEMENT": [
            65,
            60,
            55,
            40
        ],

        "OSCILLATION_CHECK": [
            55,
            65,
            55,
            65,
            55,
            65
        ]
    }

    all_results = []

    for index, (
        name,
        scores
    ) in enumerate(
        scenarios.items(),
        start=1
    ):

        source_ip = (
            f"192.0.2.{100 + index}"
        )

        print(
            f"\nSCENARIO {index}: {name}"
        )

        print(
            "-" * 90
        )

        controller = ResponseController(
            simulation_mode=True
        )

        results = run_scenario(
            controller,
            source_ip,
            scores
        )

        summary = summarize_scenario(
            name,
            results
        )

        all_results.append(
            summary
        )

        for item in results:

            result = item["result"]

            print(
                f'Score={item["score"]:<5} '
                f'State={str(result.get("state", result.get("current_state", "UNKNOWN"))):<14} '
                f'Action={str(result.get("action")):<20} '
                f'Effectiveness={str(result.get("effectiveness")):<18} '
                f'Recommendation={str(result.get("recommendation"))}'
            )

    output = {
        "evaluation": "AEGISNET END-TO-END DEFENSE EVALUATION",
        "simulation_mode": True,
        "real_network_blocking": False,
        "scenarios": all_results
    }

    path = os.path.join(
        OUTPUT_DIR,
        "response_evaluation.json"
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print()

    print("=" * 90)

    print(
        f"Created: {path}"
    )

    print(
        "End-to-end defense evaluation completed."
    )

    print("=" * 90)


if __name__ == "__main__":
    main()