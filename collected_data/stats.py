import json
from collections import defaultdict
from datetime import datetime

# Function to parse and analyze the JSON data
def analyze_json(file_path):
    # Initialize statistics containers
    event_count = defaultdict(int)
    session_durations = {}
    successful_logins = 0
    failed_logins = 0
    sessions_started = defaultdict(int)

    # Open and load the large JSON file
    with open(file_path, 'r') as file:
        for line in file:
            event = json.loads(line)

            # Track event counts
            event_id = event.get("eventid")
            if event_id:
                event_count[event_id] += 1

            # Track session durations
            session_id = event.get("session")
            if event_id == "cowrie.session.connect" and session_id:
                # Store session start timestamp
                sessions_started[session_id] = event.get("timestamp")

            elif event_id == "cowrie.session.closed" and session_id in sessions_started:
                # Calculate session duration when session is closed
                start_time = sessions_started.pop(session_id)
                start_timestamp = datetime.fromisoformat(start_time[:-1])
                end_timestamp = datetime.fromisoformat(event["timestamp"][:-1])
                duration = (end_timestamp - start_timestamp).total_seconds()
                session_durations[session_id] = duration

            # Track successful and failed login attempts
            if event_id == "cowrie.login.success":
                successful_logins += 1
            elif event_id == "cowrie.login.failed":
                failed_logins += 1

    # Print out statistics
    print("Event Count Statistics:")
    for event, count in event_count.items():
        print(f"{event}: {count}")

    print(f"\nTotal Sessions: {len(session_durations)}")
    print(f"Total Successful Logins: {successful_logins}")
    print(f"Total Failed Logins: {failed_logins}")

    print(f"\nAverage Session Duration: {sum(session_durations.values()) / len(session_durations) if session_durations else 0:.2f} seconds")

    print("\nSession Durations:")
    for session_id, duration in session_durations.items():
        print(f"Session {session_id}: {duration:.2f} seconds")

# Example usage
file_path = "/Users/abdullah/cowrie/var/log/cowrie/cowrie.json"  # Change this to your file's path
analyze_json(file_path)