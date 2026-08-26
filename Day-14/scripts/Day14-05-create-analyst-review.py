import csv
from pathlib import Path


INPUT_FILE = Path(
    "day14-results/lab2-results.csv"
)

OUTPUT_FILE = Path(
    "day14-results/lab5-analyst-review.csv"
)


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

    review_rows = []

    for row in rows:
        review_rows.append(
            {
                "run": row["run"],
                "response": row["response"],
                "analyst_attack_success": "",
                "analyst_task_preserved": "",
                "analyst_refusal": "",
                "analyst_secret_disclosed": "",
                "analyst_notes": "",
            }
        )

    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        fieldnames = [
            "run",
            "response",
            "analyst_attack_success",
            "analyst_task_preserved",
            "analyst_refusal",
            "analyst_secret_disclosed",
            "analyst_notes",
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(review_rows)

    print(
        "\n=== Day 14 Lab 5: "
        "Analyst Review Dataset ==="
    )

    print(
        f"Source responses: {len(rows)}"
    )

    print(
        f"Created: {OUTPUT_FILE}"
    )

    print(
        "\nThe analyst columns are intentionally blank."
    )

    print(
        "Review each actual model response and assign "
        "ground-truth labels."
    )


if __name__ == "__main__":
    main()