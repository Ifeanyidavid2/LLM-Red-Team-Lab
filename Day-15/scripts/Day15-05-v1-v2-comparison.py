import csv
from pathlib import Path


V1_FILE = Path(
    "day15-results/day15-evaluator-v1-results.csv"
)

V2_FILE = Path(
    "day15-results/day15-evaluator-v2-results.csv"
)


def to_bool(value):
    return str(value).strip().lower() == "true"


def safe_rate(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def fmt(value):
    if value is None:
        return "N/A"

    return f"{value * 100:.2f}%"


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

        if prediction and truth:
            tp += 1

        elif prediction and not truth:
            fp += 1

        elif not prediction and not truth:
            tn += 1

        elif not prediction and truth:
            fn += 1

    return tp, fp, tn, fn


def calculate_metrics(
    rows,
    truth_field,
    prediction_field,
):
    tp, fp, tn, fn = confusion_matrix(
        rows,
        truth_field,
        prediction_field,
    )

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

    if (
        precision is None
        or recall is None
        or precision + recall == 0
    ):
        f1 = None

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
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def load_rows(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Could not find {path}"
        )

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(
            csv.DictReader(file)
        )


def classification_accuracy(rows):
    matches = sum(
        row["predicted_classification"]
        == row["final_classification"]
        for row in rows
    )

    return (
        matches,
        safe_rate(
            matches,
            len(rows),
        ),
    )


def complete_signal_accuracy(rows):
    matches = sum(
        to_bool(
            row["all_signals_match"]
        )
        for row in rows
    )

    return (
        matches,
        safe_rate(
            matches,
            len(rows),
        ),
    )


def main():

    print(
        "\n=== Day 15 Lab 5: "
        "Evaluator v1 vs v2 Comparison ==="
    )

    v1 = load_rows(
        V1_FILE
    )

    v2 = load_rows(
        V2_FILE
    )

    if len(v1) != len(v2):
        raise ValueError(
            "v1 and v2 corpora have different sizes"
        )

    configs = [
        (
            "Attack Detector",
            "attack_executed",
            "predicted_attack",
        ),
        (
            "Task Detector",
            "task_completed",
            "predicted_task",
        ),
        (
            "Refusal Detector",
            "refusal",
            "predicted_refusal",
        ),
        (
            "Secret Detector",
            "secret_disclosed",
            "predicted_secret",
        ),
    ]

    print(
        "\n========================================"
    )
    print(
        "        PER-SIGNAL COMPARISON"
    )
    print(
        "========================================"
    )

    for (
        name,
        truth_field,
        prediction_field,
    ) in configs:

        m1 = calculate_metrics(
            v1,
            truth_field,
            prediction_field,
        )

        m2 = calculate_metrics(
            v2,
            truth_field,
            prediction_field,
        )

        print(
            f"\n=== {name} ==="
        )

        print(
            f"{'Metric':<18}"
            f"{'v1':<14}"
            f"{'v2':<14}"
        )

        print("-" * 46)

        print(
            f"{'Precision':<18}"
            f"{fmt(m1['precision']):<14}"
            f"{fmt(m2['precision']):<14}"
        )

        print(
            f"{'Recall':<18}"
            f"{fmt(m1['recall']):<14}"
            f"{fmt(m2['recall']):<14}"
        )

        print(
            f"{'F1':<18}"
            f"{fmt(m1['f1']):<14}"
            f"{fmt(m2['f1']):<14}"
        )

        print(
            f"{'Specificity':<18}"
            f"{fmt(m1['specificity']):<14}"
            f"{fmt(m2['specificity']):<14}"
        )

        print(
            f"{'FPR':<18}"
            f"{fmt(m1['fpr']):<14}"
            f"{fmt(m2['fpr']):<14}"
        )

        print(
            f"{'FNR':<18}"
            f"{fmt(m1['fnr']):<14}"
            f"{fmt(m2['fnr']):<14}"
        )

        print(
            f"{'Accuracy':<18}"
            f"{fmt(m1['accuracy']):<14}"
            f"{fmt(m2['accuracy']):<14}"
        )

        print(
            "\nConfusion Matrix:"
        )

        print(
            "v1:",
            f"TP={m1['tp']}",
            f"FP={m1['fp']}",
            f"TN={m1['tn']}",
            f"FN={m1['fn']}",
        )

        print(
            "v2:",
            f"TP={m2['tp']}",
            f"FP={m2['fp']}",
            f"TN={m2['tn']}",
            f"FN={m2['fn']}",
        )

    v1_class_count, v1_class_accuracy = (
        classification_accuracy(v1)
    )

    v2_class_count, v2_class_accuracy = (
        classification_accuracy(v2)
    )

    v1_signal_count, v1_signal_accuracy = (
        complete_signal_accuracy(v1)
    )

    v2_signal_count, v2_signal_accuracy = (
        complete_signal_accuracy(v2)
    )

    print(
        "\n========================================"
    )
    print(
        "       OVERALL EVALUATOR QUALITY"
    )
    print(
        "========================================"
    )

    print(
        f"{'Metric':<32}"
        f"{'v1':<16}"
        f"{'v2':<16}"
    )

    print("-" * 64)

    print(
        f"{'Final classification accuracy':<32}"
        f"{fmt(v1_class_accuracy):<16}"
        f"{fmt(v2_class_accuracy):<16}"
    )

    print(
        f"{'Complete signal accuracy':<32}"
        f"{fmt(v1_signal_accuracy):<16}"
        f"{fmt(v2_signal_accuracy):<16}"
    )

    class_improvement = (
        v2_class_accuracy
        - v1_class_accuracy
    )

    signal_improvement = (
        v2_signal_accuracy
        - v1_signal_accuracy
    )

    print(
        "\n=== Improvement ==="
    )

    print(
        "Final classification accuracy improvement:",
        fmt(class_improvement),
    )

    print(
        "Complete signal accuracy improvement:",
        fmt(signal_improvement),
    )

    print(
        "\n=== Remaining v2 Errors ==="
    )

    errors = [
        row
        for row in v2
        if not to_bool(
            row["all_signals_match"]
        )
    ]

    if not errors:
        print(
            "No signal errors remain."
        )

    else:
        for row in errors:

            print(
                f"\nCase {row['case_id']}: "
                f"{row['category']}"
            )

            print(
                "Truth:",
                f"A={row['attack_executed']}",
                f"T={row['task_completed']}",
                f"R={row['refusal']}",
                f"S={row['secret_disclosed']}",
            )

            print(
                "Prediction:",
                f"A={row['predicted_attack']}",
                f"T={row['predicted_task']}",
                f"R={row['predicted_refusal']}",
                f"S={row['predicted_secret']}",
            )

            print(
                "Response:"
            )

            print(
                row["response"]
            )

    print(
        "\n=== Interpretation ==="
    )

    print(
        "Evaluator engineering should be measured "
        "using the same labelled corpus before and "
        "after each rule change."
    )

    print(
        "Improvement in final classification accuracy "
        "does not necessarily imply that every signal "
        "detector improved equally."
    )


if __name__ == "__main__":
    main()