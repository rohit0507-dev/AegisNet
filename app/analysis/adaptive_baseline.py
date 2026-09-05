from collections import deque
from statistics import mean


class AdaptiveBaseline:

    def __init__(self, max_samples=20):

        self.max_samples = max_samples

        self.metrics = {
            "packet_rate": deque(maxlen=max_samples),
            "byte_rate": deque(maxlen=max_samples),
            "flow_count": deque(maxlen=max_samples),
            "unique_sources": deque(maxlen=max_samples),
            "unique_destinations": deque(maxlen=max_samples),
            "unique_ports": deque(maxlen=max_samples),
            "syn_ratio": deque(maxlen=max_samples),
            "rst_ratio": deque(maxlen=max_samples)
        }


    def update(self, window_features):

        self.metrics["packet_rate"].append(
            window_features.get(
                "average_packets_per_second",
                0
            )
        )

        self.metrics["byte_rate"].append(
            window_features.get(
                "average_bytes_per_second",
                0
            )
        )

        self.metrics["flow_count"].append(
            window_features.get(
                "flow_count",
                0
            )
        )

        self.metrics["unique_sources"].append(
            window_features.get(
                "unique_source_ips",
                0
            )
        )

        self.metrics["unique_destinations"].append(
            window_features.get(
                "unique_destination_ips",
                0
            )
        )

        self.metrics["unique_ports"].append(
            window_features.get(
                "unique_destination_ports",
                0
            )
        )

        self.metrics["syn_ratio"].append(
            window_features.get(
                "window_syn_ratio",
                0
            )
        )

        self.metrics["rst_ratio"].append(
            window_features.get(
                "window_rst_ratio",
                0
            )
        )


    def get_baseline(self):

        baseline = {}

        for metric, values in self.metrics.items():

            if values:

                baseline[metric] = mean(values)

            else:

                baseline[metric] = 0

        return baseline


    def calculate_deviation(
        self,
        metric,
        current_value
    ):

        values = self.metrics.get(metric)

        if not values:

            return 0.0

        baseline = mean(values)

        if baseline == 0:

            if current_value == 0:
                return 0.0

            return 1.0

        deviation = (
            abs(current_value - baseline)
            / baseline
        )

        return deviation


    def get_deviations(
        self,
        window_features
    ):

        current_values = {
            "packet_rate":
                window_features.get(
                    "average_packets_per_second",
                    0
                ),

            "byte_rate":
                window_features.get(
                    "average_bytes_per_second",
                    0
                ),

            "flow_count":
                window_features.get(
                    "flow_count",
                    0
                ),

            "unique_sources":
                window_features.get(
                    "unique_source_ips",
                    0
                ),

            "unique_destinations":
                window_features.get(
                    "unique_destination_ips",
                    0
                ),

            "unique_ports":
                window_features.get(
                    "unique_destination_ports",
                    0
                ),

            "syn_ratio":
                window_features.get(
                    "window_syn_ratio",
                    0
                ),

            "rst_ratio":
                window_features.get(
                    "window_rst_ratio",
                    0
                )
        }

        deviations = {}

        for metric, value in current_values.items():

            deviations[metric] = self.calculate_deviation(
                metric,
                value
            )

        return deviations


    def calculate_baseline_score(
        self,
        window_features
    ):

        deviations = self.get_deviations(
            window_features
        )

        if not deviations:

            return 0.0

        weighted_score = (
            deviations["packet_rate"] * 0.20
            + deviations["byte_rate"] * 0.20
            + deviations["flow_count"] * 0.15
            + deviations["unique_sources"] * 0.10
            + deviations["unique_destinations"] * 0.10
            + deviations["unique_ports"] * 0.10
            + deviations["syn_ratio"] * 0.10
            + deviations["rst_ratio"] * 0.05
        )

        return min(
            weighted_score,
            1.0
        )


    def sample_count(self):

        return min(
            len(self.metrics["flow_count"]),
            self.max_samples
        )

    def is_ready(self, minimum_samples=5):

        return self.sample_count() >= minimum_samples


    def reset(self):

        for values in self.metrics.values():

            values.clear()


if __name__ == "__main__":

    baseline = AdaptiveBaseline(
        max_samples=20
    )

    print("=" * 75)
    print("             AEGISNET ADAPTIVE BASELINE")
    print("=" * 75)

    normal_window = {
        "average_packets_per_second": 100,
        "average_bytes_per_second": 50000,
        "flow_count": 20,
        "unique_source_ips": 5,
        "unique_destination_ips": 8,
        "unique_destination_ports": 10,
        "window_syn_ratio": 0.05,
        "window_rst_ratio": 0.01
    }

    for _ in range(5):

        baseline.update(
            normal_window
        )

    print()
    print(
        f"Baseline samples : "
        f"{baseline.sample_count()}"
    )

    print(
        f"Baseline ready   : "
        f"{baseline.is_ready()}"
    )

    print()
    print("CURRENT BASELINE")
    print("-" * 75)

    for key, value in baseline.get_baseline().items():

        print(
            f"{key:<25}: {value:.4f}"
        )

    suspicious_window = {
        "average_packets_per_second": 1000,
        "average_bytes_per_second": 500000,
        "flow_count": 100,
        "unique_source_ips": 30,
        "unique_destination_ips": 40,
        "unique_destination_ports": 100,
        "window_syn_ratio": 0.40,
        "window_rst_ratio": 0.20
    }

    deviations = baseline.get_deviations(
        suspicious_window
    )

    score = baseline.calculate_baseline_score(
        suspicious_window
    )

    print()
    print("SUSPICIOUS WINDOW")
    print("-" * 75)

    for key, value in deviations.items():

        print(
            f"{key:<25}: {value:.4f}"
        )

    print()
    print(
        f"Baseline Anomaly Score : "
        f"{score:.4f}"
    )

    print()
    print("=" * 75)
    print(
        "Adaptive baseline engine initialized successfully."
    )
    print("=" * 75)