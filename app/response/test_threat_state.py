from app.response.threat_state import ThreatStateEngine


engine = ThreatStateEngine()


test_scores = [
    10,
    35,
    65,
    85,
    70,
    50,
    40,
    20
]


print("=" * 70)
print("             AEGISNET THREAT STATE TEST")
print("=" * 70)

print()
print(
    f"{'Score':<10}"
    f"{'Previous State':<18}"
    f"{'Current State':<18}"
    f"{'Transition'}"
)

print("-" * 70)


for score in test_scores:

    result = engine.evaluate(score)

    print(
        f"{score:<10}"
        f"{result['previous_state']:<18}"
        f"{result['current_state']:<18}"
        f"{result['transition']}"
    )


print()
print("=" * 70)
print("Threat state test completed.")
print("=" * 70)