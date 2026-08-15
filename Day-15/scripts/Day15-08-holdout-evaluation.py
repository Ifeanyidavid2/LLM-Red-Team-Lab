import csv
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec


HOLDOUT_FILE = Path(
    "day15-results/day15-holdout-corpus.csv"
)

OUTPUT_FILE = Path(
    "day15-results/day15-holdout-evaluation.csv"
)

V3_FILE = Path(
    "Day15-06-multisignal-evaluator-v3.py"
)


def load_v3():
    spec = spec_from_file_location(
        "day15_v3",
        V3_FILE,
    )

    module = module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def to_bool(value):
    return str(value).strip().lower() == "true"


def safe_divide(numerator, denominator):
    if denominator == 0:
        return None

    return numerator / denominator


def percentage(value):
    if value is None:
        return "N/A"

    return f"{value * 100:.2f}%"


def confusion_matrix(rows, truth_field, prediction_field):
    tp = fp = tn = fn = 0

    for row in rows:
        truth = to_bool(row[truth_field])
        prediction = to_bool(row[prediction_field])

        if truth and prediction:
            tp += 1

        elif not truth and prediction:
            fp += 1

        elif not truth and not prediction:
            tn += 1

        elif truth and not prediction:
            fn += 1

    return tp, fp, tn, fn


def calculate_metrics(tp, fp, tn, fn):
    accuracy = safe_divide(
        tp + tn,
        tp + fp + tn + fn,
    )

    precision = safe_divide(
        tp,
        tp + fp,
    )

    recall = safe_divide(
        tp,
        tp + fn,
    )

    specificity = safe_divide(
        tn,
        tn + fp,
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
            / (precision + recall)
        )

    fpr = safe_divide(
        fp,
        fp + tn,
    )

    fnr = safe_divide(
        fn,
        fn + tp,
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


def print_metrics(name, matrix):
    tp, fp, tn, fn = matrix

    metrics = calculate_metrics(
        tp,
        fp,
        tn,
        fn,
    )

    print(f"\n=== {name} ===")

    print(f"TP: {tp}")
    print(f"FP: {fp}")
    print(f"TN: {tn}")
    print(f"FN: {fn}")

    print(
        "Accuracy:",
        percentage(metrics["accuracy"]),
    )

    print(
        "Precision:",
        percentage(metrics["precision"]),
    )

    print(
        "Recall:",
        percentage(metrics["recall"]),
    )

    print(
        "Specificity:",
        percentage(metrics["specificity"]),
    )

    print(
        "F1 Score:",
        percentage(metrics["f1"]),
    )

    print(
        "False Positive Rate:",
        percentage(metrics["fpr"]),
    )

    print(
        "False Negative Rate:",
        percentage(metrics["fnr"]),
    )

    return metrics


def main():
    print(
        "\n=== Day 15 Lab 8: "
        "Frozen v3 Holdout Evaluation ==="
    )

    if not V3_FILE.exists():
        raise FileNotFoundError(
            f"Frozen evaluator not found: {V3_FILE}"
        )

    if not HOLDOUT_FILE.exists():
        raise FileNotFoundError(
            f"Holdout corpus not found: {HOLDOUT_FILE}"
        )

    v3 = load_v3()

    with HOLDOUT_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    results = []

    print(
        f"\nHoldout cases loaded: {len(rows)}"
    )

    print(
        "\n=== Per-Case Holdout Evaluation ==="
    )

    for row in rows:
        response = row["response"]

        attack = v3.detect_attack_execution(
            response
        )

        task = v3.detect_task_completion(
            response
        )

        refusal = v3.detect_refusal(
            response
        )

        secret = v3.detect_secret_disclosure(
            response
        )

        predicted_class = v3.classify(
            attack,
            task,
            refusal,
            secret,
        )

        truth_attack = to_bool(
            row["attack_executed"]
        )

        truth_task = to_bool(
            row["task_completed"]
        )

        truth_refusal = to_bool(
            row["refusal"]
        )

        truth_secret = to_bool(
            row["secret_disclosed"]
        )

        truth_class = row[
            "final_classification"
        ]

        all_signals_match = (
            attack == truth_attack
            and task == truth_task
            and refusal == truth_refusal
            and secret == truth_secret
        )

        classification_match = (
            predicted_class == truth_class
        )

        result = dict(row)

        result.update({
            "predicted_attack": attack,
            "predicted_task": task,
            "predicted_refusal": refusal,
            "predicted_secret": secret,
            "predicted_classification":
                predicted_class,
            "all_signals_match":
                all_signals_match,
            "classification_match":
                classification_match,
        })

        results.append(result)

        print(
            f"Case {row['case_id']} | "
            f"A={int(attack)} "
            f"T={int(task)} "
            f"R={int(refusal)} "
            f"S={int(secret)} | "
            f"Pred={predicted_class:<7} "
            f"Truth={truth_class:<7} | "
            f"{'MATCH' if classification_match else 'MISMATCH'}"
        )

    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys(),
        )

        writer.writeheader()
        writer.writerows(results)

    print(
        "\n========================================"
    )

    print(
        "          HOLDOUT SIGNAL METRICS"
    )

    print(
        "========================================"
    )

    attack_matrix = confusion_matrix(
        results,
        "attack_executed",
        "predicted_attack",
    )

    task_matrix = confusion_matrix(
        results,
        "task_completed",
        "predicted_task",
    )

    refusal_matrix = confusion_matrix(
        results,
        "refusal",
        "predicted_refusal",
    )

    secret_matrix = confusion_matrix(
        results,
        "secret_disclosed",
        "predicted_secret",
    )

    print_metrics(
        "Attack Execution Detector",
        attack_matrix,
    )

    print_metrics(
        "Task Completion Detector",
        task_matrix,
    )

    print_metrics(
        "Refusal Detector",
        refusal_matrix,
    )

    print_metrics(
        "Secret Disclosure Detector",
        secret_matrix,
    )

    total = len(results)

    signal_matches = sum(
        to_bool(row["all_signals_match"])
        for row in results
    )

    classification_matches = sum(
        to_bool(row["classification_match"])
        for row in results
    )

    print(
        "\n========================================"
    )

    print(
        "       HOLDOUT GENERALIZATION"
    )

    print(
        "========================================"
    )

    print(
        f"Final-class matches: "
        f"{classification_matches}/{total}"
    )

    print(
        f"All-signal matches: "
        f"{signal_matches}/{total}"
    )

    print(
        "\nFinal Classification Accuracy:",
        f"{classification_matches / total * 100:.2f}%"
    )

    print(
        "Complete Signal Accuracy:",
        f"{signal_matches / total * 100:.2f}%"
    )

    print(
        "\nResults saved to:"
    )

    print(OUTPUT_FILE)

    mismatches = [
        row
        for row in results
        if not to_bool(row["all_signals_match"])
    ]

    print(
        "\n========================================"
    )

    print(
        "          HOLDOUT ERRORS"
    )

    print(
        "========================================"
    )

    if not mismatches:
        print(
            "No signal-level errors detected."
        )

    else:
        print(
            f"Signal-level error cases: "
            f"{len(mismatches)}"
        )

        for row in mismatches:
            print(
                f"\nCase {row['case_id']}: "
                f"{row['category']}"
            )

            print(
                "Truth:",
                f"A={row['attack_executed']} "
                f"T={row['task_completed']} "
                f"R={row['refusal']} "
                f"S={row['secret_disclosed']}"
            )

            print(
                "Prediction:",
                f"A={row['predicted_attack']} "
                f"T={row['predicted_task']} "
                f"R={row['predicted_refusal']} "
                f"S={row['predicted_secret']}"
            )

            print(
                "Response:"
            )

            print(row["response"])

    print(
        "\n=== Interpretation Reminder ==="
    )

    print(
        "The v3 evaluator was frozen before "
        "testing this holdout corpus."
    )

    print(
        "Development accuracy and holdout "
        "accuracy should be reported separately."
    )

    print(
        "Errors on this corpus provide evidence "
        "about evaluator generalization."
    )


if __name__ == "__main__":
    main()