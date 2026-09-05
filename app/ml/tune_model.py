from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_FILE = (
    BASE_DIR
    / "data"
    / "ml"
    / "aegisnet_ml_dataset.csv"
)

RESULT_FILE = (
    BASE_DIR
    / "data"
    / "ml"
    / "model_tuning_results.csv"
)


FEATURES = [
    "packet_count",
    "total_bytes",
    "duration",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio"
]


def load_data():

    dataframe = pd.read_csv(
        DATASET_FILE
    )

    dataframe = dataframe[
        FEATURES
    ].replace(
        [np.inf, -np.inf],
        np.nan
    ).dropna()

    dataframe = dataframe[
        dataframe["packet_count"] > 0
    ]

    if len(dataframe) < 50:

        raise ValueError(
            "Not enough traffic records "
            "for model tuning."
        )

    return dataframe


def create_anomalies(dataframe):

    anomalies = dataframe.copy()

    anomalies["packet_count"] = (
        anomalies["packet_count"] * 20
    )

    anomalies["total_bytes"] = (
        anomalies["total_bytes"] * 20
    )

    anomalies["packets_per_second"] = (
        anomalies["packets_per_second"] * 20
    )

    anomalies["bytes_per_second"] = (
        anomalies["bytes_per_second"] * 20
    )

    anomalies["syn_count"] = np.maximum(
        anomalies["syn_count"] + 150,
        150
    )

    anomalies["syn_ratio"] = (
        anomalies["syn_count"]
        / anomalies["packet_count"]
    )

    anomalies["ack_ratio"] = (
        anomalies["ack_ratio"] * 0.1
    )

    anomalies["rst_ratio"] = (
        anomalies["rst_ratio"] * 0.1
    )

    return anomalies


def evaluate(
    contamination,
    train_data,
    normal_test,
    anomaly_test
):

    scaler = StandardScaler()

    X_train = scaler.fit_transform(
        train_data[FEATURES]
    )

    X_normal = scaler.transform(
        normal_test[FEATURES]
    )

    X_anomaly = scaler.transform(
        anomaly_test[FEATURES]
    )

    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )

    model.fit(
        X_train
    )

    normal_predictions = model.predict(
        X_normal
    )

    anomaly_predictions = model.predict(
        X_anomaly
    )

    predictions = np.concatenate(
        [
            normal_predictions,
            anomaly_predictions
        ]
    )

    true_labels = np.concatenate(
        [
            np.zeros(len(normal_predictions)),
            np.ones(len(anomaly_predictions))
        ]
    )

    predicted_labels = np.where(
        predictions == -1,
        1,
        0
    )

    tn, fp, fn, tp = (
        confusion_matrix(
            true_labels,
            predicted_labels
        ).ravel()
    )

    accuracy = accuracy_score(
        true_labels,
        predicted_labels
    )

    precision = precision_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    recall = recall_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    f1 = f1_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )

    return {
        "contamination": contamination,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate
    }


def main():

    print()
    print("=" * 80)
    print("             AEGISNET ISOLATION FOREST MODEL TUNING")
    print("=" * 80)

    dataframe = load_data()

    print()
    print(
        f"Available real traffic samples : "
        f"{len(dataframe)}"
    )

    train_data, test_data = train_test_split(
        dataframe,
        test_size=0.30,
        random_state=42
    )

    anomaly_test = create_anomalies(
        test_data
    )

    print(
        f"Training samples                : "
        f"{len(train_data)}"
    )

    print(
        f"Normal validation samples       : "
        f"{len(test_data)}"
    )

    print(
        f"Controlled anomaly samples      : "
        f"{len(anomaly_test)}"
    )

    contamination_values = [
        0.02,
        0.05,
        0.10,
        0.15
    ]

    results = []

    print()
    print("MODEL COMPARISON")
    print("-" * 80)

    for contamination in contamination_values:

        result = evaluate(
            contamination,
            train_data,
            test_data,
            anomaly_test
        )

        results.append(
            result
        )

        print(
            f"Contamination : "
            f"{contamination:.2f}"
        )

        print(
            f"Accuracy      : "
            f"{result['accuracy'] * 100:.2f}%"
        )

        print(
            f"Precision     : "
            f"{result['precision'] * 100:.2f}%"
        )

        print(
            f"Recall        : "
            f"{result['recall'] * 100:.2f}%"
        )

        print(
            f"F1 Score      : "
            f"{result['f1_score'] * 100:.2f}%"
        )

        print(
            f"False Positive: "
            f"{result['false_positive_rate'] * 100:.2f}%"
        )

        print("-" * 80)

    results_dataframe = pd.DataFrame(
        results
    )

    results_dataframe = (
        results_dataframe
        .sort_values(
            by=[
                "f1_score",
                "recall",
                "precision"
            ],
            ascending=False
        )
        .reset_index(drop=True)
    )

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results_dataframe.to_csv(
        RESULT_FILE,
        index=False
    )

    best = results_dataframe.iloc[0]

    print()
    print("=" * 80)
    print("                 BEST CANDIDATE MODEL")
    print("=" * 80)

    print(
        f"Contamination : "
        f"{best['contamination']:.2f}"
    )

    print(
        f"Accuracy      : "
        f"{best['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision     : "
        f"{best['precision'] * 100:.2f}%"
    )

    print(
        f"Recall        : "
        f"{best['recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score      : "
        f"{best['f1_score'] * 100:.2f}%"
    )

    print(
        f"False Positive: "
        f"{best['false_positive_rate'] * 100:.2f}%"
    )

    print()
    print(
        f"Results saved to:"
    )
    print(
        RESULT_FILE
    )

    print()
    print("=" * 80)
    print("                    TUNING COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()