import csv
from pathlib import Path


RULE_FILE = Path(
    "day15-results/day15-holdout-evaluation.csv"
)

HYBRID_FILE = Path(
    "day16-results/day16-hybrid-holdout-results.csv"
)


def to_bool(value):
    return str(value).strip().lower() == "true"


def safe_rate(num, den):
    if den == 0:
        return None
    return num / den


def pct(value):
    if value is None:
        return "N/A"
    return f"{value * 100:.2f}%"


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing file: {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def evaluate_operational_signal(
    rows,
    truth_field,
    prediction_field,
    failure_field=None,
):
    tp = fp = tn = fn = 0
    unavailable = 0

    for row in rows:

        truth = to_bool(
            row[truth_field]
        )

        failed = (
            failure_field is not None
            and to_bool(
                row[failure_field]
            )
        )

        if failed:
            unavailable += 1

            # Operationally, an unavailable evaluator
            # cannot detect a positive signal.
            if truth:
                fn += 1

            else:
                tn += 1

            continue

        prediction = to_bool(
            row[prediction_field]
        )

        if truth and prediction:
            tp += 1

        elif not truth and prediction:
            fp += 1

        elif not truth and not prediction:
            tn += 1

        elif truth and not prediction:
            fn += 1

    precision = safe_rate(
        tp,
        tp + fp,
    )

    recall = safe_rate(
        tp,
        tp + fn,
    )

    specificity = safe_rate(
        tn,
        tn + fp,
    )

    fpr = safe_rate(
        fp,
        fp + tn,
    )

    fnr = safe_rate(
        fn,
        fn + tp,
    )

    if (
        precision is None
        or recall is None
    ):
        f1 = None

    elif precision + recall == 0:
        f1 = 0

    else:
        f1 = (
            2
            * precision
            * recall
            / (
                precision
                + recall
            )
        )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "unavailable": unavailable,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def overall_quality(
    rows,
    failure_field=None,
):
    total = len(rows)

    failures = 0
    final_matches = 0
    signal_matches = 0

    successful = []

    for row in rows:

        failed = (
            failure_field is not None
            and to_bool(
                row[failure_field]
            )
        )

        if failed:
            failures += 1
            continue

        successful.append(row)

        if to_bool(
            row["classification_match"]
        ):
            final_matches += 1

        if to_bool(
            row["all_signals_match"]
        ):
            signal_matches += 1

    completion_rate = safe_rate(
        len(successful),
        total,
    )

    conditional_final = safe_rate(
        final_matches,
        len(successful),
    )

    conditional_signals = safe_rate(
        signal_matches,
        len(successful),
    )

    operational_final = safe_rate(
        final_matches,
        total,
    )

    operational_signals = safe_rate(
        signal_matches,
        total,
    )

    return {
        "total": total,
        "successful": len(successful),
        "failures": failures,
        "completion_rate": completion_rate,
        "conditional_final":
            conditional_final,
        "conditional_signals":
            conditional_signals,
        "operational_final":
            operational_final,
        "operational_signals":
            operational_signals,
    }


def main():

    print(
        "\n=== Day 16 Lab 5: "
        "Rule-Based vs Hybrid LLM Judge ==="
    )

    rules = load_csv(
        RULE_FILE
    )

    hybrid = load_csv(
        HYBRID_FILE
    )

    if len(rules) != len(hybrid):
        raise ValueError(
            "Evaluator corpora have different sizes."
        )

    rule_quality = overall_quality(
        rules
    )

    hybrid_quality = overall_quality(
        hybrid,
        failure_field="judge_failure",
    )

    print(
        "\n========================================"
    )
    print(
        "       OPERATIONAL COMPARISON"
    )
    print(
        "========================================"
    )

    print(
        f"{'Metric':<38}"
        f"{'Rules':<16}"
        f"{'Hybrid Judge':<16}"
    )

    print("-" * 70)

    print(
        f"{'Cases':<38}"
        f"{rule_quality['total']:<16}"
        f"{hybrid_quality['total']:<16}"
    )

    print(
        f"{'Evaluation Completion Rate':<38}"
        f"{pct(rule_quality['completion_rate']):<16}"
        f"{pct(hybrid_quality['completion_rate']):<16}"
    )

    print(
        f"{'Operational Final Accuracy':<38}"
        f"{pct(rule_quality['operational_final']):<16}"
        f"{pct(hybrid_quality['operational_final']):<16}"
    )

    print(
        f"{'Operational Complete-Signal Accuracy':<38}"
        f"{pct(rule_quality['operational_signals']):<16}"
        f"{pct(hybrid_quality['operational_signals']):<16}"
    )

    print(
        f"{'Conditional Final Accuracy':<38}"
        f"{pct(rule_quality['conditional_final']):<16}"
        f"{pct(hybrid_quality['conditional_final']):<16}"
    )

    print(
        f"{'Conditional Complete-Signal Accuracy':<38}"
        f"{pct(rule_quality['conditional_signals']):<16}"
        f"{pct(hybrid_quality['conditional_signals']):<16}"
    )

    print(
        "\nHybrid judge schema / execution failures:",
        hybrid_quality["failures"],
    )

    signals = [
        (
            "Attack Execution",
            "attack_executed",
            "predicted_attack",
        ),
        (
            "Task Completion",
            "task_completed",
            "predicted_task",
        ),
        (
            "Refusal",
            "refusal",
            "predicted_refusal",
        ),
        (
            "Secret Disclosure",
            "secret_disclosed",
            "predicted_secret",
        ),
    ]

    print(
        "\n========================================"
    )
    print(
        "        OPERATIONAL SIGNAL METRICS"
    )
    print(
        "========================================"
    )

    for (
        name,
        truth_field,
        prediction_field,
    ) in signals:

        rule_result = (
            evaluate_operational_signal(
                rules,
                truth_field,
                prediction_field,
            )
        )

        hybrid_result = (
            evaluate_operational_signal(
                hybrid,
                truth_field,
                prediction_field,
                failure_field="judge_failure",
            )
        )

        print(
            f"\n=== {name} ==="
        )

        print(
            f"{'Metric':<20}"
            f"{'Rules':<16}"
            f"{'Hybrid':<16}"
        )

        print("-" * 52)

        print(
            f"{'Precision':<20}"
            f"{pct(rule_result['precision']):<16}"
            f"{pct(hybrid_result['precision']):<16}"
        )

        print(
            f"{'Recall':<20}"
            f"{pct(rule_result['recall']):<16}"
            f"{pct(hybrid_result['recall']):<16}"
        )

        print(
            f"{'F1':<20}"
            f"{pct(rule_result['f1']):<16}"
            f"{pct(hybrid_result['f1']):<16}"
        )

        print(
            f"{'Specificity':<20}"
            f"{pct(rule_result['specificity']):<16}"
            f"{pct(hybrid_result['specificity']):<16}"
        )

        print(
            f"{'FPR':<20}"
            f"{pct(rule_result['fpr']):<16}"
            f"{pct(hybrid_result['fpr']):<16}"
        )

        print(
            f"{'FNR':<20}"
            f"{pct(rule_result['fnr']):<16}"
            f"{pct(hybrid_result['fnr']):<16}"
        )

        print(
            "\nRules:",
            f"TP={rule_result['tp']}",
            f"FP={rule_result['fp']}",
            f"TN={rule_result['tn']}",
            f"FN={rule_result['fn']}",
        )

        print(
            "Hybrid:",
            f"TP={hybrid_result['tp']}",
            f"FP={hybrid_result['fp']}",
            f"TN={hybrid_result['tn']}",
            f"FN={hybrid_result['fn']}",
            f"Unavailable={hybrid_result['unavailable']}",
        )

    print(
        "\n========================================"
    )
    print(
        "         COMPARATIVE FINDINGS"
    )
    print(
        "========================================"
    )

    print(
        "1. Rule-based evaluation completed all "
        "20 cases; the hybrid LLM judge produced "
        "schema/evaluation failures."
    )

    print(
        "2. Conditional LLM-judge accuracy must "
        "not be compared directly with full-corpus "
        "rule-based accuracy."
    )

    print(
        "3. Operational accuracy counts judge "
        "failures as evaluation failures."
    )

    print(
        "4. Deterministic secret detection remained "
        "the strongest component of the hybrid design."
    )

    print(
        "5. The LLM judge did not automatically "
        "solve semantic generalization problems."
    )

    print(
        "6. Semantic evaluation quality and output "
        "contract reliability are separate judge "
        "security properties."
    )


if __name__ == "__main__":
    main()