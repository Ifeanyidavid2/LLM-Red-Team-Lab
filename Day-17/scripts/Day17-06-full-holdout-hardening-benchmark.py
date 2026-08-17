import asyncio
import csv
import importlib.util
from pathlib import Path

from pyrit.prompt_target import OpenAIChatTarget
from pyrit.setup import initialize_pyrit_async


JUDGE_MODEL = "llama3.2:1b"

LAB3_FILE = Path(
    "Day17-03-utility-aware-hardened-judge.py"
)

INPUT_FILE = Path(
    "day15-results/day15-holdout-corpus.csv"
)

OUTPUT_FILE = Path(
    "day17-results/day17-hardened-holdout-results.csv"
)


def load_lab3():

    spec = importlib.util.spec_from_file_location(
        "day17_lab3",
        LAB3_FILE,
    )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(module)

    return module


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


def decision_tuple(decision):

    if (
        decision["attack"] is None
        or decision["task"] is None
        or decision["refusal"] is None
    ):
        return None

    return (
        decision["attack"],
        decision["task"],
        decision["refusal"],
    )


async def evaluate(
    lab3,
    target,
    case_id,
    response,
):

    judge_result = None
    judge_error = None

    try:

        judge_result = await lab3.judge_response(
            target,
            f"holdout-{case_id}",
            response,
        )

    except Exception as exc:

        judge_error = str(exc)

    decision = lab3.utility_aware_decision(
        response=response,
        judge_result=judge_result,
        judge_error=judge_error,
    )

    return judge_result, judge_error, decision


def confusion_matrix(
    rows,
    truth_field,
    prediction_field,
):

    tp = fp = tn = fn = 0

    for row in rows:

        # Escalated cases count as unavailable.
        # For operational sensitivity, a true positive
        # that is escalated is not an automatic detection.
        if to_bool(row["escalated"]):

            truth = to_bool(
                row[truth_field]
            )

            if truth:
                fn += 1
            else:
                tn += 1

            continue

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

        else:
            fn += 1

    return tp, fp, tn, fn


def signal_metrics(
    tp,
    fp,
    tn,
    fn,
):

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
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "fpr": fpr,
        "fnr": fnr,
        "f1": f1,
    }


async def main():

    lab3 = load_lab3()

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        db_path="day17-pyrit.db",
        load_defaults=False,
        silent=True,
    )

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Missing corpus: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:

        cases = list(
            csv.DictReader(file)
        )

    target = OpenAIChatTarget(
        model_name=JUDGE_MODEL,
        endpoint="http://localhost:11434/v1",
        api_key="ollama",
    )

    OUTPUT_FILE.parent.mkdir(
        exist_ok=True
    )

    results = []

    print(
        "\n=== Day 17 Lab 6: "
        "Full Holdout Hardening Benchmark ==="
    )

    for row in cases:

        response = row[
            "response"
        ]

        judge_result, judge_error, decision = (
            await evaluate(
                lab3,
                target,
                row["case_id"],
                response,
            )
        )

        signals = decision_tuple(
            decision
        )

        truth_signals = (
            to_bool(row["attack_executed"]),
            to_bool(row["task_completed"]),
            to_bool(row["refusal"]),
        )

        final_match = (
            decision["status"]
            == row["final_classification"]
        )

        complete_match = (
            not decision["escalated"]
            and signals == truth_signals
            and decision["secret"]
            == to_bool(
                row["secret_disclosed"]
            )
        )

        result = dict(row)

        result.update({
            "predicted_attack":
                decision["attack"],
            "predicted_task":
                decision["task"],
            "predicted_refusal":
                decision["refusal"],
            "predicted_secret":
                decision["secret"],
            "predicted_status":
                decision["status"],
            "escalated":
                decision["escalated"],
            "decision_reason":
                decision["reason"],
            "final_match":
                final_match,
            "complete_signal_match":
                complete_match,
        })

        results.append(result)

        print(
            f"Case {row['case_id']} "
            f"| Truth={row['final_classification']} "
            f"| Pred={decision['status']} "
            f"| Escalate={decision['escalated']} "
            f"| FinalMatch={final_match}"
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

    total = len(results)

    escalations = sum(
        to_bool(row["escalated"])
        for row in results
    )

    final_correct = sum(
        to_bool(row["final_match"])
        for row in results
    )

    signal_correct = sum(
        to_bool(
            row["complete_signal_match"]
        )
        for row in results
    )

    automatic_cases = (
        total - escalations
    )

    conditional_correct = sum(
        to_bool(row["final_match"])
        for row in results
        if not to_bool(
            row["escalated"]
        )
    )

    print(
        "\n========================================"
    )

    print(
        "      HARDENED HOLDOUT SUMMARY"
    )

    print(
        "========================================"
    )

    print(
        f"Total cases: {total}"
    )

    print(
        f"Automatic evaluations: "
        f"{automatic_cases}"
    )

    print(
        f"Escalations: {escalations}"
    )

    print(
        "Automatic Evaluation Rate:",
        pct(
            safe_rate(
                automatic_cases,
                total,
            )
        )
    )

    print(
        "Escalation Rate:",
        pct(
            safe_rate(
                escalations,
                total,
            )
        )
    )

    print(
        "Operational Final Accuracy:",
        pct(
            safe_rate(
                final_correct,
                total,
            )
        )
    )

    print(
        "Conditional Automatic Accuracy:",
        pct(
            safe_rate(
                conditional_correct,
                automatic_cases,
            )
        )
    )

    print(
        "Operational Complete-Signal Accuracy:",
        pct(
            safe_rate(
                signal_correct,
                total,
            )
        )
    )

    configs = [

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
        "       OPERATIONAL SIGNAL METRICS"
    )

    print(
        "========================================"
    )

    for (
        name,
        truth_field,
        prediction_field,
    ) in configs:

        matrix = confusion_matrix(
            results,
            truth_field,
            prediction_field,
        )

        metrics = signal_metrics(
            *matrix
        )

        tp, fp, tn, fn = matrix

        print(
            f"\n=== {name} ==="
        )

        print(
            f"TP={tp} FP={fp} "
            f"TN={tn} FN={fn}"
        )

        print(
            "Precision:",
            pct(
                metrics["precision"]
            )
        )

        print(
            "Recall:",
            pct(
                metrics["recall"]
            )
        )

        print(
            "F1:",
            pct(
                metrics["f1"]
            )
        )

        print(
            "Specificity:",
            pct(
                metrics["specificity"]
            )
        )

        print(
            "FPR:",
            pct(
                metrics["fpr"]
            )
        )

        print(
            "FNR:",
            pct(
                metrics["fnr"]
            )
        )

    print(
        "\n========================================"
    )

    print(
        "        DAY 16 REFERENCE"
    )

    print(
        "========================================"
    )

    print(
        "Hybrid Judge Completion: 85.00%"
    )

    print(
        "Operational Final Accuracy: 55.00%"
    )

    print(
        "Operational Complete Signals: 20.00%"
    )

    print(
        "Attack Recall: 20.00%"
    )

    print(
        "Task Recall: 12.50%"
    )

    print(
        "Refusal Recall: 0.00%"
    )

    print(
        "Secret Recall: 100.00%"
    )

    print(
        "\nResults saved to:"
    )

    print(
        OUTPUT_FILE
    )


if __name__ == "__main__":
    asyncio.run(main())