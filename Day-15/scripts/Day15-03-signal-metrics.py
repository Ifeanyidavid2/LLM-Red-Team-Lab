import csv
from pathlib import Path


INPUT_FILE = Path(
    "day15-results/day15-evaluator-v1-results.csv"
)


def to_bool(value):
    return str(value).strip().lower() == "true"


def safe_rate(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def fmt_percent(value):
    if value is None:
        return "N/A"

    return f"{value * 100:.2f}%"


def confusion_matrix(
    rows,
    truth_field,
    prediction_field,
):
    tp = 0
    fp = 0
    tn = 0
    fn = 0

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
    tp,
    fp,
    tn,
    fn,
):
    total = (
        tp + fp + tn + fn
    )

    accuracy = safe_rate(
        tp + tn,
        total,
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
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def evaluate_signal(
    rows,
    name,
    truth_field,
    prediction_field,
):
    tp, fp, tn, fn = confusion_matrix(
        rows,
        truth_field,
        prediction_field,
    )

    metrics = calculate_metrics(
        tp,
        fp,
        tn,
        fn,
    )

    print(
        f"\n=== {name} ==="
    )

    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"TN: {tn}")
    print(f"FN: {fn}")

    print(
        "Accuracy:",
        fmt_percent(
            metrics["accuracy"]
        ),
    )

    print(
        "Precision:",
        fmt_percent(
            metrics["precision"]
        ),
    )

    print(
        "Recall:",
        fmt_percent(
            metrics["recall"]
        ),
    )

    print(
        "Specificity:",
        fmt_percent(
            metrics["specificity"]
        ),
    )

    print(
        "F1 Score:",
        fmt_percent(
            metrics["f1"]
        ),
    )

    print(
        "False Positive Rate:",
        fmt_percent(
            metrics["fpr"]
        ),
    )

    print(
        "False Negative Rate:",
        fmt_percent(
            metrics["fnr"]
        ),
    )

    return {
        "signal": name,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        **metrics,
    }


def main():

    print(
        "\n=== Day 15 Lab 3: "
        "Per-Signal Evaluator Metrics ==="
    )

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Could not find {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:

        rows = list(
            csv.DictReader(file)
        )

    print(
        f"Cases loaded: {len(rows)}"
    )

    signal_configs = [
        (
            "Attack Execution Detector",
            "attack_executed",
            "predicted_attack",
        ),
        (
            "Task Completion Detector",
            "task_completed",
            "predicted_task",
        ),
        (
            "Refusal Detector",
            "refusal",
            "predicted_refusal",
        ),
        (
            "Secret Disclosure Detector",
            "secret_disclosed",
            "predicted_secret",
        ),
    ]

    results = []

    for (
        name,
        truth_field,
        prediction_field,
    ) in signal_configs:

        result = evaluate_signal(
            rows,
            name,
            truth_field,
            prediction_field,
        )

        results.append(result)

    print(
        "\n========================================"
    )

    print(
        "        SIGNAL COMPARISON"
    )

    print(
        "========================================"
    )

    print(
        f"{'Signal':<30}"
        f"{'Precision':<12}"
        f"{'Recall':<12}"
        f"{'F1':<12}"
        f"{'FPR':<12}"
        f"{'FNR':<12}"
    )

    print("-" * 90)

    for result in results:

        print(
            f"{result['signal']:<30}"
            f"{fmt_percent(result['precision']):<12}"
            f"{fmt_percent(result['recall']):<12}"
            f"{fmt_percent(result['f1']):<12}"
            f"{fmt_percent(result['fpr']):<12}"
            f"{fmt_percent(result['fnr']):<12}"
        )

    print(
        "\n=== Error Analysis ==="
    )

    for (
        name,
        truth_field,
        prediction_field,
    ) in signal_configs:

        print(
            f"\n{name}:"
        )

        errors = []

        for row in rows:

            truth = to_bool(
                row[truth_field]
            )

            prediction = to_bool(
                row[prediction_field]
            )

            if truth != prediction:

                if prediction:
                    error_type = (
                        "FALSE POSITIVE"
                    )

                else:
                    error_type = (
                        "FALSE NEGATIVE"
                    )

                errors.append(
                    (
                        row["case_id"],
                        row["category"],
                        error_type,
                    )
                )

        if not errors:
            print(
                "No errors."
            )

        else:
            for (
                case_id,
                category,
                error_type,
            ) in errors:

                print(
                    f"- Case {case_id}: "
                    f"{category} "
                    f"({error_type})"
                )

    print(
        "\n=== Interpretation ==="
    )

    print(
        "Final classification accuracy alone "
        "cannot reveal which evaluator component "
        "is weak."
    )

    print(
        "Per-signal confusion matrices show "
        "whether errors come from attack detection, "
        "task detection, refusal detection, or "
        "secret-disclosure detection."
    )


if __name__ == "__main__":
    main()