import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE_FILE = BASE_DIR / "data" / "aegisnet.db"
ML_DATASET_DIR = BASE_DIR / "data" / "ml"
ML_DATASET_FILE = ML_DATASET_DIR / "aegisnet_ml_dataset.csv"


class DatasetBuilder:

    def __init__(self):

        self.database_file = DATABASE_FILE

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

    def load_data(self):

        connection = sqlite3.connect(
            self.database_file
        )

        query = """
            SELECT
                packet_count,
                total_bytes,
                duration,
                packets_per_second,
                bytes_per_second,
                average_packet_size,
                syn_count,
                ack_count,
                fin_count,
                rst_count,
                syn_ratio,
                ack_ratio,
                fin_ratio,
                rst_ratio
            FROM flow_records
        """

        dataframe = pd.read_sql_query(
            query,
            connection
        )

        connection.close()

        return dataframe

    def clean_data(self, dataframe):

        dataframe = dataframe.copy()

        dataframe = dataframe.replace(
            [float("inf"), float("-inf")],
            pd.NA
        )

        dataframe = dataframe.dropna(
            subset=self.features
        )

        dataframe = dataframe[
            dataframe["packet_count"] > 0
        ]

        dataframe = dataframe[
            dataframe["total_bytes"] >= 0
        ]

        dataframe = dataframe.reset_index(
            drop=True
        )

        return dataframe

    def save_dataset(self, dataframe):

        ML_DATASET_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        dataframe[self.features].to_csv(
            ML_DATASET_FILE,
            index=False
        )

    def build(self):

        dataframe = self.load_data()

        print("=" * 70)
        print("             AEGISNET ML DATASET BUILDER")
        print("=" * 70)

        print(
            f"Database records loaded : "
            f"{len(dataframe)}"
        )

        dataframe = self.clean_data(
            dataframe
        )

        print(
            f"Records after cleaning  : "
            f"{len(dataframe)}"
        )

        print(
            f"Features selected       : "
            f"{len(self.features)}"
        )

        self.save_dataset(dataframe)

        print()
        print(
            f"Dataset saved to        : "
            f"{ML_DATASET_FILE}"
        )

        print()
        print("FEATURES")
        print("-" * 70)

        for index, feature in enumerate(
            self.features,
            start=1
        ):

            print(
                f"{index:2}. {feature}"
            )

        print()
        print("DATASET SHAPE")
        print("-" * 70)

        print(
            f"Rows    : {dataframe.shape[0]}"
        )

        print(
            f"Columns : {dataframe.shape[1]}"
        )

        print()
        print("FEATURE SUMMARY")
        print("-" * 70)

        print(
            dataframe[self.features].describe()
        )

        print()
        print("=" * 70)
        print("ML dataset created successfully.")
        print("=" * 70)

        return dataframe


if __name__ == "__main__":

    builder = DatasetBuilder()

    builder.build()