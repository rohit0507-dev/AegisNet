from pathlib import Path
import pandas as pd
import numpy as np

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

from app.ml.anomaly_detector import AnomalyDetector


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
    / "evaluation_results.csv"
)


def create_test_dataset():

    dataframe = pd.read_csv(
        DATASET_FILE
    )

    features = [
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

    dataframe = dataframe[
        features
    ].replace(
        [np.inf, -np.inf],
        np.nan
    ).dropna()

    dataframe = dataframe[
        dataframe["packet_count"] > 0
    ]

    if len(dataframe) < 20:

        raise ValueError(
            "Not enough real traffic records "
            "for evaluation."
        )

    normal = dataframe.sample(
        n=min(50, len(dataframe)),
        random_state=42
    ).copy()

    normal["label"] = 0

    anomalies = normal.copy()

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

    anomalies["syn_count"] = (
        anomalies["syn_count"] + 150
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

    anomalies["label"] = 1

    test_data = pd.concat(
        [
            normal,
            anomalies
        ],
        ignore_index=True
    )

    return test_data


def evaluate_model():

    detector = AnomalyDetector()

    detector.load_model()

    dataframe = create_test_dataset()

    features = detector.features

    X = dataframe[features]

    X_scaled = detector.scaler.transform(
        X
    )

    predictions = detector.model.predict(
        X_scaled
    )

    predicted_labels = [

        1 if prediction == -1
        else 0

        for prediction in predictions
    ]

    true_labels = dataframe[
        "label"
    ].tolist()

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

    detection_rate = (

        tp / (tp + fn)

        if (tp + fn) > 0

        else 0
    )

    dataframe["prediction"] = (
        predicted_labels
    )

    dataframe["correct"] = (
        dataframe["label"]
        == dataframe["prediction"]
    )

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    dataframe.to_csv(
        RESULT_FILE,
        index=False
    )

    print()
    print("=" * 75)
    print(
        "       AEGISNET REAL-TRAFFIC-BASED "
        "ML EVALUATION"
    )
    print("=" * 75)

    print()

    print(
        f"Real baseline samples : "
        f"{len(dataframe) // 2}"
    )

    print(
        f"Normal test samples   : "
        f"{sum(dataframe['label'] == 0)}"
    )

    print(
        f"Anomaly test samples  : "
        f"{sum(dataframe['label'] == 1)}"
    )

    print()

    print("CONFUSION MATRIX")
    print("-" * 75)

    print(
        f"True Negatives       : "
        f"{tn}"
    )

    print(
        f"False Positives      : "
        f"{fp}"
    )

    print(
        f"False Negatives      : "
        f"{fn}"
    )

    print(
        f"True Positives       : "
        f"{tp}"
    )

    print()

    print("PERFORMANCE METRICS")
    print("-" * 75)

    print(
        f"Accuracy             : "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Precision            : "
        f"{precision * 100:.2f}%"
    )

    print(
        f"Recall               : "
        f"{recall * 100:.2f}%"
    )

    print(
        f"F1 Score             : "
        f"{f1 * 100:.2f}%"
    )

    print(
        f"False Positive Rate  : "
        f"{false_positive_rate * 100:.2f}%"
    )

    print(
        f"Detection Rate       : "
        f"{detection_rate * 100:.2f}%"
    )

    print()

    print(
        "Results saved to:"
    )

    print(
        RESULT_FILE
    )

    print()

    print("=" * 75)
    print(
        "             ML EVALUATION COMPLETE"
    )
    print("=" * 75)


if __name__ == "__main__":

    evaluate_model()