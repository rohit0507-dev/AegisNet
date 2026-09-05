from app.ml.anomaly_detector import AnomalyDetector


detector = AnomalyDetector()


normal_flow = {
    "packet_count": 10,
    "total_bytes": 5000,
    "duration": 2,
    "packets_per_second": 5,
    "bytes_per_second": 2500,
    "average_packet_size": 500,
    "syn_count": 1,
    "ack_count": 5,
    "fin_count": 1,
    "rst_count": 0,
    "syn_ratio": 0.1,
    "ack_ratio": 0.5,
    "fin_ratio": 0.1,
    "rst_ratio": 0.0
}


suspicious_flow = {
    "packet_count": 2000,
    "total_bytes": 1000000,
    "duration": 2,
    "packets_per_second": 1000,
    "bytes_per_second": 500000,
    "average_packet_size": 500,
    "syn_count": 500,
    "ack_count": 20,
    "fin_count": 5,
    "rst_count": 2,
    "syn_ratio": 0.25,
    "ack_ratio": 0.01,
    "fin_ratio": 0.0025,
    "rst_ratio": 0.001
}


print("=" * 70)
print("             AEGISNET ML PREDICTION TEST")
print("=" * 70)


normal_result = detector.predict(normal_flow)

print()
print("NORMAL FLOW")
print("-" * 70)
print(f"Anomaly          : {normal_result['is_anomaly']}")
print(f"Prediction       : {normal_result['prediction']}")
print(f"Anomaly Score    : {normal_result['anomaly_score']:.6f}")
print(f"Anomaly Strength : {normal_result['anomaly_strength']}")
print(f"ML Confidence    : {normal_result['ml_confidence']:.2%}")


suspicious_result = detector.predict(suspicious_flow)

print()
print("SUSPICIOUS FLOW")
print("-" * 70)
print(f"Anomaly          : {suspicious_result['is_anomaly']}")
print(f"Prediction       : {suspicious_result['prediction']}")
print(f"Anomaly Score    : {suspicious_result['anomaly_score']:.6f}")
print(f"Anomaly Strength : {suspicious_result['anomaly_strength']}")
print(f"ML Confidence    : {suspicious_result['ml_confidence']:.2%}")


print()
print("=" * 70)
print("ML prediction test completed.")
print("=" * 70)