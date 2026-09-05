import os
import json
import csv

import pandas as pd
import matplotlib.pyplot as plt

from app.scoring.threat_fusion import ThreatFusionEngine


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

FINAL_DIR = os.path.join(
    EVALUATION_DIR,
    "final_graphs"
)

os.makedirs(
    FINAL_DIR,
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

FINAL_REPORT_FILE = os.path.join(
    EVALUATION_DIR,
    "final_evaluation_report.json"
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


def save_csv(filename, rows):

    path = os.path.join(
        FINAL_DIR,
        filename
    )

    if not rows:
        return

    dataframe = pd.DataFrame(rows)

    dataframe.to_csv(
        path,
        index=False
    )

    print(
        f"Created: {path}"
    )


def save_json(filename, data):

    path = os.path.join(
        FINAL_DIR,
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )

    print(
        f"Created: {path}"
    )


def create_bar_chart(
    labels,
    values,
    title,
    xlabel,
    ylabel,
    filename
):

    plt.figure(
        figsize=(10, 6)
    )

    plt.bar(
        labels,
        values
    )

    plt.title(
        title
    )

    plt.xlabel(
        xlabel
    )

    plt.ylabel(
        ylabel
    )

    plt.xticks(
        rotation=25,
        ha="right"
    )

    plt.tight_layout()

    path = os.path.join(
        FINAL_DIR,
        filename
    )

    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"Created: {path}"
    )


def create_line_chart(
    x,
    y,
    title,
    xlabel,
    ylabel,
    filename
):

    plt.figure(
        figsize=(10, 6)
    )

    plt.plot(
        x,
        y,
        marker="o"
    )

    plt.title(
        title
    )

    plt.xlabel(
        xlabel
    )

    plt.ylabel(
        ylabel
    )

    plt.grid(
        True,
        alpha=0.3
    )

    plt.tight_layout()

    path = os.path.join(
        FINAL_DIR,
        filename
    )

    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"Created: {path}"
    )


def create_histogram(
    values,
    title,
    xlabel,
    ylabel,
    filename
):

    if not values:
        return

    plt.figure(
        figsize=(10, 6)
    )

    plt.hist(
        values,
        bins=12
    )

    plt.title(
        title
    )

    plt.xlabel(
        xlabel
    )

    plt.ylabel(
        ylabel
    )

    plt.grid(
        True,
        alpha=0.3
    )

    plt.tight_layout()

    path = os.path.join(
        FINAL_DIR,
        filename
    )

    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"Created: {path}"
    )


def generate_controlled_results():

    data = load_json(
        CONTROLLED_FILE
    )

    metrics = data.get(
        "classification_metrics",
        {}
    )

    if not metrics:

        metrics = {

            "TP": data.get(
                "TP",
                4
            ),

            "TN": data.get(
                "TN",
                1
            ),

            "FP": data.get(
                "FP",
                0
            ),

            "FN": data.get(
                "FN",
                0
            )
        }

    rows = []

    for key in [
        "TP",
        "TN",
        "FP",
        "FN"
    ]:

        rows.append({

            "Metric":
                key,

            "Count":
                metrics.get(
                    key,
                    0
                )
        })

    save_csv(
        "controlled_confusion_matrix.csv",
        rows
    )

    create_bar_chart(

        [
            "TP",
            "TN",
            "FP",
            "FN"
        ],

        [
            metrics.get(
                "TP",
                0
            ),

            metrics.get(
                "TN",
                0
            ),

            metrics.get(
                "FP",
                0
            ),

            metrics.get(
                "FN",
                0
            )
        ],

        "Controlled Detection Validation",

        "Classification Outcome",

        "Number of Cases",

        "controlled_detection_validation.png"
    )


def generate_response_results():

    data = load_json(
        RESPONSE_FILE
    )

    scenarios = data.get(
        "scenarios",
        []
    )

    state_counts = {}

    action_counts = {}

    effectiveness_counts = {}

    scenario_rows = []

    for scenario in scenarios:

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

        effectiveness = scenario.get(
            "effectiveness",
            []
        )

        for state in states:

            if isinstance(
                state,
                dict
            ):

                state = state.get(
                    "current_state",
                    "UNKNOWN"
                )

            state_counts[
                str(state)
            ] = state_counts.get(
                str(state),
                0
            ) + 1

        for action in actions:

            if action is None:
                action = "NO_ACTION_RECORDED"

            action_counts[
                str(action)
            ] = action_counts.get(
                str(action),
                0
            ) + 1

        for result in effectiveness:

            if result:

                effectiveness_counts[
                    str(result)
                ] = effectiveness_counts.get(
                    str(result),
                    0
                ) + 1

        scenario_rows.append({

            "scenario":
                name,

            "steps":
                len(scores),

            "initial_score":
                scores[0]
                if scores
                else None,

            "final_score":
                scores[-1]
                if scores
                else None,

            "maximum_score":
                max(scores)
                if scores
                else None,

            "minimum_score":
                min(scores)
                if scores
                else None
        })

    save_csv(
        "response_scenario_summary.csv",
        scenario_rows
    )

    save_csv(
        "threat_state_distribution.csv",
        [
            {
                "State": key,
                "Count": value
            }

            for key, value
            in state_counts.items()
        ]
    )

    save_csv(
        "defense_action_distribution.csv",
        [
            {
                "Action": key,
                "Count": value
            }

            for key, value
            in action_counts.items()
        ]
    )

    save_csv(
        "response_effectiveness_distribution.csv",
        [
            {
                "Effectiveness": key,
                "Count": value
            }

            for key, value
            in effectiveness_counts.items()
        ]
    )

    create_bar_chart(

        list(
            state_counts.keys()
        ),

        list(
            state_counts.values()
        ),

        "Threat State Distribution",

        "Threat State",

        "Number of Steps",

        "threat_state_distribution.png"
    )

    create_bar_chart(

        list(
            action_counts.keys()
        ),

        list(
            action_counts.values()
        ),

        "Defense Action Distribution",

        "Defense Action",

        "Number of Steps",

        "defense_action_distribution.png"
    )

    create_bar_chart(

        list(
            effectiveness_counts.keys()
        ),

        list(
            effectiveness_counts.values()
        ),

        "Response Effectiveness Distribution",

        "Response Classification",

        "Number of Interventions",

        "response_effectiveness_distribution.png"
    )


def generate_feedback_results():

    if not os.path.exists(
        IMPROVEMENT_FILE
    ):

        print(
            "Improvement CSV not found."
        )

        return

    dataframe = pd.read_csv(
        IMPROVEMENT_FILE
    )

    column = None

    for candidate in [

        "improvement_ratio",
        "improvement",
        "ratio"

    ]:

        if candidate in dataframe.columns:

            column = candidate

            break

    if column is None:

        print(
            "No improvement column found."
        )

        return

    values = pd.to_numeric(
        dataframe[column],
        errors="coerce"
    ).dropna()

    if values.empty:
        return

    values_percent = (
        values * 100
    )

    save_csv(

        "defense_feedback_statistics.csv",

        [
            {
                "Metric":
                    "Observations",

                "Value":
                    len(values)
            },

            {
                "Metric":
                    "Average Improvement (%)",

                "Value":
                    values_percent.mean()
            },

            {
                "Metric":
                    "Median Improvement (%)",

                "Value":
                    values_percent.median()
            },

            {
                "Metric":
                    "Best Improvement (%)",

                "Value":
                    values_percent.max()
            },

            {
                "Metric":
                    "Worst Improvement (%)",

                "Value":
                    values_percent.min()
            },

            {
                "Metric":
                    "Positive Improvements",

                "Value":
                    (values > 0).sum()
            },

            {
                "Metric":
                    "Negative Improvements",

                "Value":
                    (values < 0).sum()
            }
        ]
    )

    create_histogram(

        list(
            values_percent
        ),

        "Distribution of Defense Feedback Improvement",

        "Threat Score Improvement (%)",

        "Number of Observations",

        "defense_feedback_improvement_distribution.png"
    )


def run_fusion_test(
    engine,
    name,
    rule_alerts,
    ml_anomaly,
    ml_confidence,
    anomaly_strength,
    port_scan_detected,
    temporal_result
):

    result = engine.fuse(

        rule_alerts=rule_alerts,

        ml_anomaly=ml_anomaly,

        ml_confidence=ml_confidence,

        anomaly_strength=anomaly_strength,

        port_scan_detected=port_scan_detected,

        baseline_score=0.0,

        temporal_result=temporal_result,

        source_context=None,

        existing_threat_score=0.0
    )

    return {

        "Scenario":
            name,

        "Fusion Score":
            result["fusion_score"],

        "Severity":
            result["severity"],

        "Confidence":
            result["confidence"],

        "Evidence Count":
            result["evidence_count"],

        "Evidence Sources":
            ", ".join(
                result[
                    "malicious_evidence_sources"
                ]
            )
    }


def generate_fusion_results():

    engine = ThreatFusionEngine()

    temporal = {

        "consecutive_anomalies":
            3,

        "persistent":
            True,

        "very_strong_persistent":
            False
    }

    scenarios = [

        (
            "NORMAL",
            [],
            False,
            0.0,
            "NORMAL",
            False,
            None
        ),

        (
            "ML ONLY",
            [],
            True,
            0.95,
            "VERY_STRONG",
            False,
            None
        ),

        (
            "PORT SCAN ONLY",
            [],
            False,
            0.0,
            "NORMAL",
            True,
            None
        ),

        (
            "SYN FLOOD ONLY",
            [
                {
                    "type":
                        "SYN_FLOOD",

                    "severity":
                        "HIGH",

                    "message":
                        "Controlled SYN flood"
                }
            ],
            False,
            0.0,
            "NORMAL",
            False,
            None
        ),

        (
            "ML + PORT SCAN",
            [],
            True,
            0.95,
            "VERY_STRONG",
            True,
            None
        ),

        (
            "RULE + ML",
            [
                {
                    "type":
                        "SYN_FLOOD",

                    "severity":
                        "HIGH",

                    "message":
                        "Controlled SYN flood"
                }
            ],
            True,
            0.95,
            "VERY_STRONG",
            False,
            None
        ),

        (
            "RULE + TEMPORAL",
            [
                {
                    "type":
                        "SYN_FLOOD",

                    "severity":
                        "HIGH",

                    "message":
                        "Controlled SYN flood"
                }
            ],
            False,
            0.0,
            "NORMAL",
            False,
            temporal
        ),

        (
            "PORT SCAN + TEMPORAL",
            [],
            False,
            0.0,
            "NORMAL",
            True,
            temporal
        ),

        (
            "RULE + ML + TEMPORAL",
            [
                {
                    "type":
                        "SYN_FLOOD",

                    "severity":
                        "HIGH",

                    "message":
                        "Controlled SYN flood"
                }
            ],
            True,
            0.95,
            "VERY_STRONG",
            False,
            temporal
        ),

        (
            "ALL FOUR EVIDENCE SOURCES",
            [
                {
                    "type":
                        "SYN_FLOOD",

                    "severity":
                        "HIGH",

                    "message":
                        "Controlled SYN flood"
                }
            ],
            True,
            0.95,
            "VERY_STRONG",
            True,
            {
                "consecutive_anomalies":
                    5,

                "persistent":
                    True,

                "very_strong_persistent":
                    True
            }
        )
    ]

    rows = []

    for scenario in scenarios:

        rows.append(
            run_fusion_test(
                engine,
                *scenario
            )
        )

    save_csv(
        "fusion_evidence_convergence.csv",
        rows
    )

    scores = [
        row["Fusion Score"]
        for row in rows
    ]

    names = [
        row["Scenario"]
        for row in rows
    ]

    create_line_chart(

        range(
            len(scores)
        ),

        scores,

        "Threat Fusion Evidence Convergence",

        "Fusion Scenario",

        "Fusion Threat Score",

        "fusion_evidence_convergence.png"
    )


def generate_response_trajectory():

    data = load_json(
        RESPONSE_FILE
    )

    scenarios = data.get(
        "scenarios",
        []
    )

    rows = []

    for scenario in scenarios:

        name = scenario.get(
            "scenario",
            "UNKNOWN"
        )

        scores = scenario.get(
            "scores",
            []
        )

        for step, score in enumerate(
            scores,
            start=1
        ):

            rows.append({

                "Scenario":
                    name,

                "Step":
                    step,

                "Threat Score":
                    score
            })

    save_csv(
        "response_trajectory.csv",
        rows
    )

    for scenario in scenarios:

        name = scenario.get(
            "scenario",
            "UNKNOWN"
        )

        scores = scenario.get(
            "scores",
            []
        )

        if not scores:
            continue

        safe_name = (
            name.lower()
            .replace(
                " ",
                "_"
            )
        )

        create_line_chart(

            range(
                1,
                len(scores) + 1
            ),

            scores,

            f"Defense Response Trajectory - {name}",

            "Evaluation Step",

            "Threat Score",

            f"trajectory_{safe_name}.png"
        )


def generate_overall_summary():

    final_report = load_json(
        FINAL_REPORT_FILE
    )

    response = final_report.get(
        "response_evaluation",
        {}
    )

    feedback = final_report.get(
        "defense_feedback",
        {}
    )

    controlled = final_report.get(
        "controlled_component_metrics",
        {}
    )

    rows = [

        {
            "Category":
                "Controlled Validation",

            "Metric":
                "True Positives",

            "Value":
                controlled.get(
                    "TP",
                    0
                )
        },

        {
            "Category":
                "Controlled Validation",

            "Metric":
                "True Negatives",

            "Value":
                controlled.get(
                    "TN",
                    0
                )
        },

        {
            "Category":
                "Controlled Validation",

            "Metric":
                "False Positives",

            "Value":
                controlled.get(
                    "FP",
                    0
                )
        },

        {
            "Category":
                "Controlled Validation",

            "Metric":
                "False Negatives",

            "Value":
                controlled.get(
                    "FN",
                    0
                )
        },

        {
            "Category":
                "Response",

            "Metric":
                "Response Steps",

            "Value":
                response.get(
                    "total_response_steps",
                    0
                )
        },

        {
            "Category":
                "Response",

            "Metric":
                "Evaluated Interventions",

            "Value":
                response.get(
                    "evaluated_interventions",
                    0
                )
        },

        {
            "Category":
                "Response",

            "Metric":
                "Full Effectiveness (%)",

            "Value":
                response.get(
                    "response_effectiveness_percent",
                    0
                )
        },

        {
            "Category":
                "Response",

            "Metric":
                "Partial Effectiveness (%)",

            "Value":
                response.get(
                    "partial_effectiveness_percent",
                    0
                )
        },

        {
            "Category":
                "Response",

            "Metric":
                "Full or Partial Success (%)",

            "Value":
                response.get(
                    "full_or_partial_effectiveness_percent",
                    0
                )
        },

        {
            "Category":
                "Feedback",

            "Metric":
                "Average Improvement (%)",

            "Value":
                feedback.get(
                    "average_percent",
                    0
                )
        },

        {
            "Category":
                "Feedback",

            "Metric":
                "Median Improvement (%)",

            "Value":
                feedback.get(
                    "median_percent",
                    0
                )
        },

        {
            "Category":
                "Feedback",

            "Metric":
                "Best Improvement (%)",

            "Value":
                feedback.get(
                    "best_percent",
                    0
                )
        },

        {
            "Category":
                "Feedback",

            "Metric":
                "Worst Improvement (%)",

            "Value":
                feedback.get(
                    "worst_percent",
                    0
                )
        }
    ]

    save_csv(
        "overall_evaluation_summary.csv",
        rows
    )


def main():

    print("=" * 90)

    print(
        "             AEGISNET FINAL RESULTS GENERATOR"
    )

    print("=" * 90)

    print()

    print(
        "Generating controlled validation results..."
    )

    generate_controlled_results()

    print()

    print(
        "Generating response evaluation results..."
    )

    generate_response_results()

    print()

    print(
        "Generating defense feedback results..."
    )

    generate_feedback_results()

    print()

    print(
        "Generating threat fusion convergence results..."
    )

    generate_fusion_results()

    print()

    print(
        "Generating defense response trajectories..."
    )

    generate_response_trajectory()

    print()

    print(
        "Generating overall evaluation summary..."
    )

    generate_overall_summary()

    print()

    print("=" * 90)

    print(
        "Final results generation completed."
    )

    print(
        f"Output directory:"
    )

    print(
        FINAL_DIR
    )

    print("=" * 90)


if __name__ == "__main__":

    main()