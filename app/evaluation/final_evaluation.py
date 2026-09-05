import os
import json
import csv
import statistics
from collections import Counter


BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

EVALUATION_DIR = os.path.join(
    BASE_DIR,
    "data",
    "evaluation"
)

os.makedirs(
    EVALUATION_DIR,
    exist_ok=True
)


CONTROLLED_FILE = os.path.join(
    EVALUATION_DIR,
    "controlled_evaluation.json"
)

RESPONSE_FILE = os.path.join(
    EVALUATION_DIR,
    "response_evaluation.json"
)

IMPROVEMENT_FILE = os.path.join(
    EVALUATION_DIR,
    "defense_feedback_improvement.csv"
)


def load_json(path):

    if not os.path.exists(path):
        return {}

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def safe_float(value, default=0.0):

    try:

        if value is None:
            return default

        return float(value)

    except (
        TypeError,
        ValueError
    ):

        return default


def flatten_response_results(response_data):

    records = []

    scenarios = response_data.get(
        "scenarios",
        []
    )

    for scenario in scenarios:

        scenario_name = scenario.get(
            "scenario",
            "UNKNOWN"
        )

        scores = scenario.get(
            "scores",
            []
        )

        states = scenario.get(
            "states",
            []
        )

        actions = scenario.get(
            "actions",
            []
        )

        effectiveness = scenario.get(
            "effectiveness",
            []
        )

        recommendations = scenario.get(
            "recommendations",
            []
        )

        count = max(
            len(scores),
            len(states),
            len(actions),
            len(effectiveness),
            len(recommendations)
        )

        for i in range(count):

            state = (
                states[i]
                if i < len(states)
                else "UNKNOWN"
            )

            if isinstance(
                state,
                dict
            ):

                state = state.get(
                    "current_state",
                    state.get(
                        "state",
                        "UNKNOWN"
                    )
                )

            records.append({

                "scenario":
                    scenario_name,

                "score":
                    scores[i]
                    if i < len(scores)
                    else None,

                "state":
                    state,

                "action":
                    actions[i]
                    if i < len(actions)
                    else None,

                "effectiveness":
                    effectiveness[i]
                    if i < len(effectiveness)
                    else None,

                "recommendation":
                    recommendations[i]
                    if i < len(recommendations)
                    else None
            })

    return records


def calculate_response_metrics(records):

    state_counter = Counter()

    action_counter = Counter()

    effectiveness_counter = Counter()

    recommendation_counter = Counter()

    for record in records:

        state_counter[
            str(record["state"])
        ] += 1

        action = record["action"]

        if action is None:
            action = "NO_ACTION_RECORDED"

        action_counter[
            str(action)
        ] += 1

        effectiveness = record[
            "effectiveness"
        ]

        if effectiveness:

            effectiveness_counter[
                str(effectiveness)
            ] += 1

        recommendation = record[
            "recommendation"
        ]

        if recommendation:

            recommendation_counter[
                str(recommendation)
            ] += 1

    evaluated = sum(
        effectiveness_counter.values()
    )

    effective = effectiveness_counter.get(
        "EFFECTIVE",
        0
    )

    partially_effective = effectiveness_counter.get(
        "PARTIALLY_EFFECTIVE",
        0
    )

    ineffective = effectiveness_counter.get(
        "INEFFECTIVE",
        0
    )

    if evaluated > 0:

        effectiveness_rate = (
            effective / evaluated
        ) * 100

        partial_effectiveness_rate = (
            partially_effective / evaluated
        ) * 100

        ineffective_rate = (
            ineffective / evaluated
        ) * 100

        useful_response_rate = (
            (
                effective
                + partially_effective
            )
            / evaluated
        ) * 100

    else:

        effectiveness_rate = 0.0

        partial_effectiveness_rate = 0.0

        ineffective_rate = 0.0

        useful_response_rate = 0.0

    return {

        "total_response_steps":
            len(records),

        "states":
            dict(state_counter),

        "actions":
            dict(action_counter),

        "effectiveness":
            dict(effectiveness_counter),

        "recommendations":
            dict(recommendation_counter),

        "evaluated_interventions":
            evaluated,

        "effective_interventions":
            effective,

        "partially_effective_interventions":
            partially_effective,

        "ineffective_interventions":
            ineffective,

        "response_effectiveness_percent":
            effectiveness_rate,

        "partial_effectiveness_percent":
            partial_effectiveness_rate,

        "ineffective_percent":
            ineffective_rate,

        "full_or_partial_effectiveness_percent":
            useful_response_rate
    }


def calculate_controlled_metrics(
    controlled_data
):

    metrics = {}

    classification = controlled_data.get(
        "classification_metrics",
        {}
    )

    if classification:

        for key in [

            "TP",
            "TN",
            "FP",
            "FN",
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "accuracy"

        ]:

            if key in classification:

                metrics[key] = classification[
                    key
                ]

    if not metrics:

        for key in [

            "tp",
            "tn",
            "fp",
            "fn",
            "precision",
            "recall",
            "f1",
            "fpr",
            "accuracy"

        ]:

            if key in controlled_data:

                metrics[key] = controlled_data[
                    key
                ]

    return metrics


def load_improvement_data():

    values = []

    if not os.path.exists(
        IMPROVEMENT_FILE
    ):

        return values

    with open(
        IMPROVEMENT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(
            file
        )

        for row in reader:

            for key in [

                "improvement_ratio",
                "improvement",
                "ratio"

            ]:

                if key in row:

                    value = safe_float(
                        row[key],
                        None
                    )

                    if value is not None:

                        values.append(
                            value
                        )

                    break

    return values


def improvement_metrics(values):

    if not values:

        return {

            "count":
                0,

            "average_percent":
                0.0,

            "median_percent":
                0.0,

            "best_percent":
                0.0,

            "worst_percent":
                0.0,

            "positive_improvements":
                0,

            "negative_improvements":
                0
        }

    positive = [

        value
        for value in values
        if value > 0

    ]

    negative = [

        value
        for value in values
        if value < 0

    ]

    return {

        "count":
            len(values),

        "average_percent":
            statistics.mean(values) * 100,

        "median_percent":
            statistics.median(values) * 100,

        "best_percent":
            max(values) * 100,

        "worst_percent":
            min(values) * 100,

        "positive_improvements":
            len(positive),

        "negative_improvements":
            len(negative)
    }


def print_section(title):

    print()

    print(
        "=" * 90
    )

    print(title)

    print(
        "=" * 90
    )


def main():

    print(
        "=" * 90
    )

    print(
        "             AEGISNET FINAL SYSTEM EVALUATION"
    )

    print(
        "=" * 90
    )

    controlled_data = load_json(
        CONTROLLED_FILE
    )

    response_data = load_json(
        RESPONSE_FILE
    )

    response_records = flatten_response_results(
        response_data
    )

    controlled_metrics = calculate_controlled_metrics(
        controlled_data
    )

    response_metrics = calculate_response_metrics(
        response_records
    )

    improvements = load_improvement_data()

    improvement_result = improvement_metrics(
        improvements
    )

    final_report = {

        "project":
            "AegisNet",

        "evaluation_type":
            "Controlled component validation and end-to-end defense evaluation",

        "simulation_mode":
            True,

        "real_network_blocking":
            False,

        "controlled_component_metrics":
            controlled_metrics,

        "response_evaluation":
            response_metrics,

        "defense_feedback":
            improvement_result
    }

    print_section(
        "1. CONTROLLED COMPONENT VALIDATION"
    )

    if controlled_metrics:

        for key, value in controlled_metrics.items():

            print(
                f"{key:<25}: {value}"
            )

    else:

        print(
            "Controlled classification metrics "
            "were not found."
        )

    print_section(
        "2. END-TO-END RESPONSE EVALUATION"
    )

    print(
        f"Total response steps      : "
        f"{response_metrics['total_response_steps']}"
    )

    print(
        f"Evaluated interventions   : "
        f"{response_metrics['evaluated_interventions']}"
    )

    print(
        f"Effective interventions   : "
        f"{response_metrics['effective_interventions']}"
    )

    print(
        f"Partially effective       : "
        f"{response_metrics['partially_effective_interventions']}"
    )

    print(
        f"Ineffective interventions : "
        f"{response_metrics['ineffective_interventions']}"
    )

    print(
        f"Full effectiveness        : "
        f"{response_metrics['response_effectiveness_percent']:.2f}%"
    )

    print(
        f"Partial effectiveness     : "
        f"{response_metrics['partial_effectiveness_percent']:.2f}%"
    )

    print(
        f"Ineffective               : "
        f"{response_metrics['ineffective_percent']:.2f}%"
    )

    print(
        f"Full or partial success   : "
        f"{response_metrics['full_or_partial_effectiveness_percent']:.2f}%"
    )

    print()

    print(
        "Threat states:"
    )

    for key, value in response_metrics[
        "states"
    ].items():

        print(
            f"  {key:<20}: {value}"
        )

    print()

    print(
        "Defense actions:"
    )

    for key, value in response_metrics[
        "actions"
    ].items():

        print(
            f"  {key:<25}: {value}"
        )

    print()

    print(
        "Recommendations:"
    )

    for key, value in response_metrics[
        "recommendations"
    ].items():

        print(
            f"  {key:<25}: {value}"
        )

    print_section(
        "3. DEFENSE FEEDBACK EFFECTIVENESS"
    )

    print(
        f"Intervention observations : "
        f"{improvement_result['count']}"
    )

    print(
        f"Average improvement       : "
        f"{improvement_result['average_percent']:.2f}%"
    )

    print(
        f"Median improvement        : "
        f"{improvement_result['median_percent']:.2f}%"
    )

    print(
        f"Best improvement          : "
        f"{improvement_result['best_percent']:.2f}%"
    )

    print(
        f"Worst improvement         : "
        f"{improvement_result['worst_percent']:.2f}%"
    )

    print(
        f"Positive improvements     : "
        f"{improvement_result['positive_improvements']}"
    )

    print(
        f"Negative improvements     : "
        f"{improvement_result['negative_improvements']}"
    )

    print_section(
        "4. SCENARIO VALIDATION"
    )

    for scenario in response_data.get(
        "scenarios",
        []
    ):

        name = scenario.get(
            "scenario",
            "UNKNOWN"
        )

        scores = scenario.get(
            "scores",
            []
        )

        states = scenario.get(
            "states",
            []
        )

        actions = scenario.get(
            "actions",
            []
        )

        print()

        print(
            f"{name}"
        )

        print(
            f"  Scores  : {scores}"
        )

        print(
            f"  States  : {states}"
        )

        print(
            f"  Actions : {actions}"
        )

    report_path = os.path.join(
        EVALUATION_DIR,
        "final_evaluation_report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            final_report,
            file,
            indent=4
        )

    summary_path = os.path.join(
        EVALUATION_DIR,
        "final_evaluation_summary.csv"
    )

    summary_rows = [

        [
            "Metric",
            "Value"
        ],

        [
            "Response Steps",
            response_metrics[
                "total_response_steps"
            ]
        ],

        [
            "Evaluated Interventions",
            response_metrics[
                "evaluated_interventions"
            ]
        ],

        [
            "Effective Interventions",
            response_metrics[
                "effective_interventions"
            ]
        ],

        [
            "Partially Effective Interventions",
            response_metrics[
                "partially_effective_interventions"
            ]
        ],

        [
            "Ineffective Interventions",
            response_metrics[
                "ineffective_interventions"
            ]
        ],

        [
            "Full Effectiveness (%)",
            response_metrics[
                "response_effectiveness_percent"
            ]
        ],

        [
            "Partial Effectiveness (%)",
            response_metrics[
                "partial_effectiveness_percent"
            ]
        ],

        [
            "Ineffective (%)",
            response_metrics[
                "ineffective_percent"
            ]
        ],

        [
            "Full or Partial Effectiveness (%)",
            response_metrics[
                "full_or_partial_effectiveness_percent"
            ]
        ],

        [
            "Average Improvement (%)",
            improvement_result[
                "average_percent"
            ]
        ],

        [
            "Median Improvement (%)",
            improvement_result[
                "median_percent"
            ]
        ],

        [
            "Best Improvement (%)",
            improvement_result[
                "best_percent"
            ]
        ],

        [
            "Worst Improvement (%)",
            improvement_result[
                "worst_percent"
            ]
        ],

        [
            "Positive Improvements",
            improvement_result[
                "positive_improvements"
            ]
        ],

        [
            "Negative Improvements",
            improvement_result[
                "negative_improvements"
            ]
        ]
    ]

    with open(
        summary_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(
            file
        )

        writer.writerows(
            summary_rows
        )

    print_section(
        "5. OUTPUT FILES"
    )

    print(
        f"Created: {report_path}"
    )

    print(
        f"Created: {summary_path}"
    )

    print()

    print(
        "Final evaluation completed successfully."
    )

    print(
        "=" * 90
    )


if __name__ == "__main__":

    main()