import sqlite3
import json

DB_PATH = "day12-pyrit.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get the newest Day 12 attack result
attack = cursor.execute("""
    SELECT *
    FROM AttackResultEntries
    ORDER BY timestamp DESC
    LIMIT 1
""").fetchone()

if attack is None:
    print("No Day 12 attack results found.")
    conn.close()
    raise SystemExit

print("\n=== Latest Day 12 PyRIT Attack Result ===")
print("Attack ID:", attack["id"])
print("Conversation ID:", attack["conversation_id"])
print("Objective:", attack["objective"])
print("Outcome:", attack["outcome"])
print("Outcome Reason:", attack["outcome_reason"])
print("Executed Turns:", attack["executed_turns"])
print("Execution Time (ms):", attack["execution_time_ms"])
print("Timestamp:", attack["timestamp"])

conversation_id = attack["conversation_id"]

print("\n=== Conversation ===")

messages = cursor.execute("""
    SELECT *
    FROM PromptMemoryEntries
    WHERE conversation_id = ?
    ORDER BY sequence ASC, timestamp ASC
""", (conversation_id,)).fetchall()

for message in messages:
    print(f"\n[{message['role']}]")
    print("Original:", message["original_value"])

    if message["converted_value"]:
        print("Converted:", message["converted_value"])

print("\n=== Objective Score ===")

score = None

if attack["last_score_id"]:
    score = cursor.execute("""
        SELECT *
        FROM ScoreEntries
        WHERE id = ?
    """, (attack["last_score_id"],)).fetchone()

if score:
    print("Score ID:", score["id"])
    print("Score Type:", score["score_type"])
    print("Score Value:", score["score_value"])
    print("Score Description:", score["score_value_description"])
    print("Rationale:", score["score_rationale"])
    print("Objective:", score["objective"])
else:
    print("No objective score found.")

print("\n=== Labels ===")

labels = attack["labels"]

try:
    parsed_labels = json.loads(labels) if labels else {}
    print(json.dumps(parsed_labels, indent=2))
except Exception:
    print(labels)

conn.close()