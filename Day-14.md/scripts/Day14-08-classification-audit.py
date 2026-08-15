import csv
from pathlib import Path


INPUT_FILE = Path(
    "day14-results/lab7-multiscenario-results.csv"
)


def to_bool(value):
    return value.strip().lower() == "true"


def main():
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
        "\n=== Day 14 Lab 8: "
        "Classification Audit ==="
    )

    print(
        f"Total benchmark responses: {len(rows)}"
    )

    flagged = []

    for row in rows:

        attack = to_bool(
            row["attack_success"]
        )

        task = to_bool(
            row["task_preserved"]
        )

        refusal = to_bool(
            row["refusal"]
        )

        secret = to_bool(
            row["secret_disclosed"]
        )

        reasons = []

        if attack:
            reasons.append(
                "ATTACK_SUCCESS"
            )

        if secret:
            reasons.append(
                "SECRET_DISCLOSURE"
            )

        if attack and task:
            reasons.append(
                "ATTACK_AND_TASK_PRESERVED"
            )

        if refusal and task:
            reasons.append(
                "REFUSAL_AND_TASK_PRESERVED"
            )

        if (
            row["scenario"] == "clean_baseline"
            and secret
        ):
            reasons.append(
                "CLEAN_BASELINE_SECRET_ANOMALY"
            )

        if reasons:
            flagged.append(
                (
                    row,
                    reasons,
                )
            )

    print(
        f"Flagged responses: {len(flagged)}"
    )

    for row, reasons in flagged:

        print(
            "\n========================================"
        )

        print(
            "Scenario:",
            row["scenario"],
        )

        print(
            "Run:",
            row["run"],
        )

        print(
            "Flags:",
            ", ".join(reasons),
        )

        print(
            "\nAutomated Classification:"
        )

        print(
            "Attack Success:",
            row["attack_success"],
        )

        print(
            "Task Preserved:",
            row["task_preserved"],
        )

        print(
            "Refusal:",
            row["refusal"],
        )

        print(
            "Secret Disclosed:",
            row["secret_disclosed"],
        )

        print(
            "\n--- MODEL RESPONSE ---"
        )

        print(
            row["response"]
        )

        print(
            "--- END RESPONSE ---"
        )

    print(
        "\n========================================"
    )

    print(
        "          AUDIT SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        "Review each flagged response manually."
    )

    print(
        "Determine whether the automated labels "
        "reflect the actual security behavior."
    )

    print(
        "Do not treat automated benchmark metrics "
        "as ground truth until unusual classifications "
        "have been validated."
    )


if __name__ == "__main__":
    main()