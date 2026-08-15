import csv
from pathlib import Path


DEV_FILE = Path(
    "day15-results/day15-evaluator-v3-results.csv"
)

HOLDOUT_FILE = Path(
    "day15-results/day15-holdout-evaluation.csv"
)


def to_bool(value):
    return str(value).strip().lower() == "true"


def safe_rate(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def pct(value):
    if value is None:
        return "N/A"

    return f"{value * 100:.2f}%"


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def confusion_matrix(
    rows,
    truth_field,
    prediction_field,
):
    tp = fp = tn = fn = 0

    for row in rows:
        truth = to_bool(
            row[truth_field]
        )

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

    return tp, fp, tn, fn


def metrics(tp, fp, tn, fn):
    accuracy = safe_rate(
        tp + tn,
        tp + fp + tn + fn,
    )

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

    if precision is None or recall is None:
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
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def overall_quality(rows):
    total = len(rows)

    class_matches = sum(
        to_bool(
            row["classification_match"]
        )
        for row in rows
    )

    signal_matches = sum(
        to_bool(
            row["all_signals_match"]
        )
        for row in rows
    )

    return {
        "total": total,
        "class_matches": class_matches,
        "signal_matches": signal_matches,
        "class_accuracy":
            safe_rate(class_matches, total),
        "signal_accuracy":
            safe_rate(signal_matches, total),
    }


def main():

    print(
        "\n=== Day 15 Lab 10: "
        "Final Evaluator Validation Summary ==="
    )

    development = load_csv(
        DEV_FILE
    )

    holdout = load_csv(
        HOLDOUT_FILE
    )

    dev_quality = overall_quality(
        development
    )

    holdout_quality = overall_quality(
        holdout
    )

    print(
        "\n========================================"
    )
    print(
        " DEVELOPMENT VS HOLDOUT"
    )
    print(
        "========================================"
    )

    print(
        f"{'Metric':<34}"
        f"{'Development':<18}"
        f"{'Holdout':<18}"
    )

    print("-" * 70)

    print(
        f"{'Cases':<34}"
        f"{dev_quality['total']:<18}"
        f"{holdout_quality['total']:<18}"
    )

    print(
        f"{'Final Classification Accuracy':<34}"
        f"{pct(dev_quality['class_accuracy']):<18}"
        f"{pct(holdout_quality['class_accuracy']):<18}"
    )

    print(
        f"{'Complete Signal Accuracy':<34}"
        f"{pct(dev_quality['signal_accuracy']):<18}"
        f"{pct(holdout_quality['signal_accuracy']):<18}"
    )

    class_gap = (
        dev_quality["class_accuracy"]
        - holdout_quality["class_accuracy"]
    )

    signal_gap = (
        dev_quality["signal_accuracy"]
        - holdout_quality["signal_accuracy"]
    )

    print(
        "\nGeneralization gap:"
    )

    print(
        "Final classification:",
        f"{class_gap * 100:.2f} percentage points"
    )

    print(
        "Complete signals:",
        f"{signal_gap * 100:.2f} percentage points"
    )

    signal_configs = [
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
        " HOLDOUT PER-SIGNAL PERFORMANCE"
    )
    print(
        "========================================"
    )

    for (
        name,
        truth_field,
        prediction_field,
    ) in signal_configs:

        matrix = confusion_matrix(
            holdout,
            truth_field,
            prediction_field,
        )

        result = metrics(
            *matrix
        )

        tp, fp, tn, fn = matrix

        print(
            f"\n=== {name} ==="
        )

        print(
            f"TP={tp} "
            f"FP={fp} "
            f"TN={tn} "
            f"FN={fn}"
        )

        print(
            "Precision:",
            pct(result["precision"])
        )

        print(
            "Recall:",
            pct(result["recall"])
        )

        print(
            "F1:",
            pct(result["f1"])
        )

        print(
            "Specificity:",
            pct(result["specificity"])
        )

        print(
            "FPR:",
            pct(result["fpr"])
        )

        print(
            "FNR:",
            pct(result["fnr"])
        )

    print(
        "\n========================================"
    )
    print(
        " KEY ENGINEERING FINDINGS"
    )
    print(
        "========================================"
    )

    findings = [
        (
            "1. The evaluator reached 100% "
            "development-set accuracy after iterative "
            "rule tuning."
        ),
        (
            "2. Frozen evaluation on unseen holdout "
            "data reduced final-classification "
            "accuracy to 60%."
        ),
        (
            "3. Complete-signal accuracy fell from "
            "100% to 35% on the holdout corpus."
        ),
        (
            "4. Attack detection maintained 100% "
            "precision but recall dropped to 20%, "
            "producing an 80% false-negative rate."
        ),
        (
            "5. Task detection maintained 100% "
            "precision but recall dropped to 37.5%."
        ),
        (
            "6. Refusal detection failed to recognize "
            "all four unseen refusal paraphrases, "
            "producing 0% recall."
        ),
        (
            "7. Secret disclosure detection retained "
            "100% precision and recall because the "
            "protected value had a stable deterministic "
            "representation."
        ),
        (
            "8. Correct final classifications sometimes "
            "masked incorrect underlying signal "
            "detections."
        ),
        (
            "9. Rule-based evaluator performance must "
            "be tested on unseen language before "
            "security claims are made."
        ),
        (
            "10. Any future tuning based on the current "
            "holdout corpus requires a new untouched "
            "test corpus for unbiased validation."
        ),
    ]

    for finding in findings:
        print(finding)

    print(
        "\n========================================"
    )
    print(
        " FINAL DAY 15 CONCLUSION"
    )
    print(
        "========================================"
    )

    print(
        "\nThe evaluation system itself must be "
        "treated as a security-critical component."
    )

    print(
        "\nPerfect performance on a development "
        "dataset did not translate into reliable "
        "performance on unseen language."
    )

    print(
        "\nThe strongest generalized detector was "
        "deterministic secret-disclosure detection."
    )

    print(
        "\nSemantic attack execution, task completion, "
        "and refusal required broader language "
        "understanding than narrow handcrafted rules "
        "could provide."
    )

    print(
        "\nTherefore evaluator quality must be "
        "measured using labelled ground truth, "
        "per-signal metrics, frozen holdout testing, "
        "and repeated independent validation."
    )


if __name__ == "__main__":
    main()