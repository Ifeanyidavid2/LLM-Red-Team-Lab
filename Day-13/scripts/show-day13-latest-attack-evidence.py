import sqlite3
import json

DB_PATH = "day13-pyrit.db"


def pretty_json(value):
    if not value:
        return ""

    try:
        return json.dumps(json.loads(value), indent=2)
    except Exception:
        return value


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get latest Day 13 attack result.
    attack = cursor.execute(
        """
        SELECT *
        FROM AttackResultEntries
        ORDER BY timestamp DESC
        LIMIT 1
        """
    ).fetchone()

    if not attack:
        print("No AttackResultEntries found.")
        conn.close()
        return

    print("\n=== Latest Day 13 PyRIT Attack Result ===")

    print("Attack ID:", attack["id"])
    print("Conversation ID:", attack["conversation_id"])
    print("Objective:", attack["objective"])
    print("Outcome:", attack["outcome"])
    print("Outcome Reason:", attack["outcome_reason"])
    print("Executed Turns:", attack["executed_turns"])
    print("Execution Time (ms):", attack["execution_time_ms"])
    print("Timestamp:", attack["timestamp"])

    conversation_id = attack["conversation_id"]

    # Retrieve conversation.
    messages = cursor.execute(
        """
        SELECT *
        FROM PromptMemoryEntries
        WHERE conversation_id = ?
        ORDER BY sequence ASC
        """,
        (conversation_id,),
    ).fetchall()

    print("\n=== Conversation ===")

    for message in messages:
        print(f"\n[{message['role']}]")
        print("Original:", message["original_value"])

        if message["converted_value"]:
            print("Converted:", message["converted_value"])

    # Retrieve objective score.
    if attack["last_score_id"]:

        score = cursor.execute(
            """
            SELECT *
            FROM ScoreEntries
            WHERE id = ?
            """,
            (attack["last_score_id"],),
        ).fetchone()

        if score:
            print("\n=== Objective Score ===")
            print("Score ID:", score["id"])
            print("Score Type:", score["score_type"])
            print("Score Value:", score["score_value"])
            print(
                "Score Description:",
                score["score_value_description"] or "",
            )
            print(
                "Rationale:",
                score["score_rationale"] or "",
            )
            print(
                "Objective:",
                score["objective"] or "",
            )

    print("\n=== Labels ===")
    print(pretty_json(attack["labels"]))

    conn.close()


if __name__ == "__main__":
    main()