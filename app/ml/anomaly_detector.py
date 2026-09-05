from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parents[2]

DATASET_FILE = (
    BASE_DIR
    / "data"
    / "ml"
    / "aegisnet_ml_dataset.csv"
)

MODEL_DIR = (
    BASE_DIR
    / "data"
    / "ml"
    / "models"
)

MODEL_FILE = (
    MODEL_DIR
    / "isolation_forest.joblib"
)

SCALER_FILE = (
    MODEL_DIR
    / "feature_scaler.joblib"
)


class AnomalyDetector:

    def __init__(self):

        self.features = [

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

        self.model = None

        self.scaler = None

        self.contamination = 0.15

        self.weak_threshold = 0.05

        self.moderate_threshold = 0.15

        self.strong_threshold = 0.25

    # =========================================================
    # TRAIN MODEL
    # =========================================================

    def train(self):

        if not DATASET_FILE.exists():

            raise FileNotFoundError(
                f"Dataset not found: {DATASET_FILE}"
            )

        dataframe = pd.read_csv(
            DATASET_FILE
        )

        missing_features = [

            feature

            for feature in self.features

            if feature not in dataframe.columns
        ]

        if missing_features:

            raise ValueError(
                "Dataset is missing required features: "
                + ", ".join(missing_features)
            )

        dataframe = dataframe[
            self.features
        ]

        dataframe = dataframe.replace(
            [
                float("inf"),
                float("-inf")
            ],
            float("nan")
        ).dropna()

        dataframe = dataframe[
            dataframe["packet_count"] > 0
        ]

        if dataframe.empty:

            raise ValueError(
                "No valid training samples found."
            )

        X = dataframe[
            self.features
        ]

        print()

        print("=" * 75)

        print(
            "          AEGISNET ISOLATION FOREST TRAINING"
        )

        print("=" * 75)

        print()

        print(
            f"Training samples : {len(X)}"
        )

        print(
            f"Features         : {len(self.features)}"
        )

        print(
            f"Contamination    : {self.contamination}"
        )

        self.scaler = StandardScaler()

        X_scaled = self.scaler.fit_transform(
            X
        )

        self.model = IsolationForest(

            n_estimators=300,

            contamination=self.contamination,

            random_state=42,

            n_jobs=-1
        )

        self.model.fit(
            X_scaled
        )

        predictions = self.model.predict(
            X_scaled
        )

        anomaly_count = sum(
            prediction == -1
            for prediction in predictions
        )

        normal_count = sum(
            prediction == 1
            for prediction in predictions
        )

        anomaly_rate = (

            anomaly_count
            / len(X)
            * 100
        )

        MODEL_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        joblib.dump(
            self.model,
            MODEL_FILE
        )

        joblib.dump(
            self.scaler,
            SCALER_FILE
        )

        print()

        print(
            "TRAINING RESULT"
        )

        print(
            "-" * 75
        )

        print(
            f"Normal samples   : {normal_count}"
        )

        print(
            f"Anomalous samples: {anomaly_count}"
        )

        print(
            f"Anomaly rate     : {anomaly_rate:.2f}%"
        )

        print()

        print(
            "MODEL FILES"
        )

        print(
            "-" * 75
        )

        print(
            f"Model  : {MODEL_FILE}"
        )

        print(
            f"Scaler : {SCALER_FILE}"
        )

        print()

        print("=" * 75)

        print(
            "Isolation Forest trained successfully."
        )

        print("=" * 75)

    # =========================================================
    # LOAD MODEL
    # =========================================================

    def load_model(self):

        if not MODEL_FILE.exists():

            raise FileNotFoundError(
                "Isolation Forest model not found: "
                f"{MODEL_FILE}"
            )

        if not SCALER_FILE.exists():

            raise FileNotFoundError(
                "Feature scaler not found: "
                f"{SCALER_FILE}"
            )

        self.model = joblib.load(
            MODEL_FILE
        )

        self.scaler = joblib.load(
            SCALER_FILE
        )

    # =========================================================
    # ANOMALY STRENGTH
    # =========================================================

    def calculate_anomaly_strength(
        self,
        anomaly_score,
        is_anomaly
    ):

        anomaly_score = float(
            anomaly_score
        )

        is_anomaly = bool(
            is_anomaly
        )

        magnitude = abs(
            anomaly_score
        )

        # -----------------------------------------------------
        # Isolation Forest prediction is the primary anomaly
        # decision. The decision function is then used to
        # estimate anomaly strength.
        # -----------------------------------------------------

        if not is_anomaly:

            return {

                "strength": "NORMAL",

                "confidence": 0.0
            }

        # -----------------------------------------------------
        # ANOMALOUS FLOW
        # -----------------------------------------------------

        if magnitude < self.weak_threshold:

            strength = "WEAK"

        elif magnitude < self.moderate_threshold:

            strength = "MODERATE"

        elif magnitude < self.strong_threshold:

            strength = "STRONG"

        else:

            strength = "VERY_STRONG"

        confidence = min(
            magnitude / self.strong_threshold,
            1.0
        )

        # An anomaly must have a non-zero confidence.
        # This prevents an actual Isolation Forest anomaly
        # from becoming invisible to the threat fusion layer.
        if confidence <= 0.0:

            confidence = 0.01

        return {

            "strength": strength,

            "confidence": float(
                confidence
            )
        }

    # =========================================================
    # PREDICTION
    # =========================================================

    def predict(self, features):

        if (
            self.model is None
            or self.scaler is None
        ):

            self.load_model()

        if not isinstance(
            features,
            dict
        ):

            raise TypeError(
                "features must be a dictionary."
            )

        missing_features = [

            feature

            for feature in self.features

            if feature not in features
        ]

        if missing_features:

            raise ValueError(
                "Missing required flow features: "
                + ", ".join(missing_features)
            )

        dataframe = pd.DataFrame(
            [features],
            columns=self.features
        )

        dataframe = dataframe.replace(
            [
                float("inf"),
                float("-inf")
            ],
            float("nan")
        )

        if dataframe.isnull().any().any():

            raise ValueError(
                "Flow contains invalid numeric values."
            )

        X = dataframe[
            self.features
        ]

        X_scaled = self.scaler.transform(
            X
        )

        prediction = self.model.predict(
            X_scaled
        )[0]

        anomaly_score = self.model.decision_function(
            X_scaled
        )[0]

        is_anomaly = (
            int(prediction) == -1
        )

        strength_result = (
            self.calculate_anomaly_strength(
                anomaly_score,
                is_anomaly
            )
        )

        anomaly_strength = (
            strength_result["strength"]
        )

        confidence = (
            strength_result["confidence"]
        )

        return {

            # Primary fields used by AegisNet
            "is_anomaly":
                bool(is_anomaly),

            "anomaly":
                bool(is_anomaly),

            "anomaly_score":
                float(anomaly_score),

            "confidence":
                float(confidence),

            "anomaly_strength":
                anomaly_strength,

            # Backward-compatible fields
            "ml_confidence":
                float(confidence),

            "prediction":
                int(prediction)
        }


# =============================================================
# DIRECT TRAINING
# =============================================================

if __name__ == "__main__":

    detector = AnomalyDetector()

    detector.train()