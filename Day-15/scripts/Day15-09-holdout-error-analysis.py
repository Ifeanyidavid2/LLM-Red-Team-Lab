import csv
from collections import Counter
from pathlib import Path


INPUT_FILE = Path(
    "day15-results/day15-holdout-evaluation.csv"
)

OUTPUT_FILE = Path(
    "day15-results/day15-holdout-error-analysis.txt"
)


def to_bool(value):
    return str(value).strip().lower() == "true"


def signal_error_type(truth, prediction):
    if truth and not prediction:
        return "FALSE NEGATIVE"

    if not truth and prediction:
        return "FALSE POSITIVE"

    return None


def main():

    print(
        "\n=== Day 15 Lab 9: "
        "Holdout Error Analysis ==="
    )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    signal_fields = {
        "Attack Execution":
            ("attack_executed", "predicted_attack"),

        "Task Completion":
            ("task_completed", "predicted_task"),

        "Refusal":
            ("refusal", "predicted_refusal"),

        "Secret Disclosure":
            ("secret_disclosed", "predicted_secret"),
    }

    report = []

    report.append(
        "DAY 15 HOLDOUT ERROR ANALYSIS"
    )

    report.append("=" * 70)

    report.append(
        f"Total holdout cases: {len(rows)}"
    )

    class_errors = [
        row for row in rows
        if not to_bool(row["classification_match"])
    ]

    signal_errors = [
        row for row in rows
        if not to_bool(row["all_signals_match"])
    ]

    report.append(
        f"Final-class errors: {len(class_errors)}"
    )

    report.append(
        f"Cases with one or more signal errors: "
        f"{len(signal_errors)}"
    )

    report.append("")

    # ------------------------------------------
    # Signal error analysis
    # ------------------------------------------

    for signal_name, fields in signal_fields.items():

        truth_field, prediction_field = fields

        false_positives = []
        false_negatives = []

        for row in rows:

            truth = to_bool(
                row[truth_field]
            )

            prediction = to_bool(
                row[prediction_field]
            )

            error = signal_error_type(
                truth,
                prediction,
            )

            if error == "FALSE POSITIVE":
                false_positives.append(row)

            elif error == "FALSE NEGATIVE":
                false_negatives.append(row)

        report.append(
            f"{signal_name.upper()} DETECTOR"
        )

        report.append("-" * 70)

        report.append(
            f"False positives: "
            f"{len(false_positives)}"
        )

        report.append(
            f"False negatives: "
            f"{len(false_negatives)}"
        )

        if false_positives:

            report.append(
                "\nFalse Positive Cases:"
            )

            for row in false_positives:
                report.append(
                    f"- Case {row['case_id']} "
                    f"({row['category']})"
                )

        if false_negatives:

            report.append(
                "\nFalse Negative Cases:"
            )

            for row in false_negatives:
                report.append(
                    f"- Case {row['case_id']} "
                    f"({row['category']}): "
                    f"{row['response']}"
                )

        report.append("")

    # ------------------------------------------
    # Final classification errors
    # ------------------------------------------

    report.append(
        "FINAL CLASSIFICATION ERRORS"
    )

    report.append("-" * 70)

    for row in class_errors:

        report.append(
            f"\nCase {row['case_id']} "
            f"({row['category']})"
        )

        report.append(
            f"Truth: "
            f"{row['final_classification']}"
        )

        report.append(
            f"Prediction: "
            f"{row['predicted_classification']}"
        )

        report.append(
            f"Response: {row['response']}"
        )

    # ------------------------------------------
    # Category concentration
    # ------------------------------------------

    report.append("")
    report.append(
        "ERROR CONCENTRATION BY CATEGORY"
    )

    report.append("-" * 70)

    category_counts = Counter(
        row["category"]
        for row in signal_errors
    )

    for category, count in (
        category_counts.most_common()
    ):
        report.append(
            f"{category}: {count}"
        )

    # ------------------------------------------
    # Generalization findings
    # ------------------------------------------

    report.append("")
    report.append(
        "GENERALIZATION FINDINGS"
    )

    report.append("-" * 70)

    report.append(
        "1. The evaluator achieved 100% accuracy "
        "on the development corpus but did not "
        "maintain that performance on unseen data."
    )

    report.append(
        "2. Attack detection showed strong precision "
        "but poor holdout recall, indicating that the "
        "rules were too specific to previously observed "
        "attack-execution wording."
    )

    report.append(
        "3. Task completion detection also suffered "
        "from low recall when legitimate completion "
        "was expressed using unseen paraphrases."
    )

    report.append(
        "4. The refusal detector failed to generalize "
        "to new refusal expressions such as "
        "'decline' and 'won't answer'."
    )

    report.append(
        "5. Secret disclosure detection generalized "
        "perfectly because the protected synthetic "
        "value had a stable deterministic representation."
    )

    report.append(
        "6. Some signal-level failures were masked by "
        "correct final classifications. A separate "
        "signal-accuracy metric is therefore necessary."
    )

    report.append(
        "7. Rule-based evaluator performance should "
        "not be reported solely on the corpus used "
        "during evaluator development."
    )

    report.append("")
    report.append(
        "SECURITY ENGINEERING CONCLUSION"
    )

    report.append("-" * 70)

    report.append(
        "The frozen holdout evaluation demonstrated "
        "that perfect development-set performance did "
        "not imply reliable generalization."
    )

    report.append(
        "The evaluator was highly specific but "
        "insufficiently sensitive to novel semantic "
        "expressions of attack execution, task "
        "completion, and refusal."
    )

    report.append(
        "Future evaluator improvements should be "
        "validated against a new test set rather than "
        "reusing this holdout corpus as proof of "
        "generalization."
    )

    final_report = "\n".join(report)

    print(final_report)

    OUTPUT_FILE.write_text(
        final_report,
        encoding="utf-8",
    )

    print(
        "\nSaved to:"
    )

    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()