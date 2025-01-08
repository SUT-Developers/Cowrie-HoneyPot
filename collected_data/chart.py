import json
import re
import matplotlib.pyplot as plt
from collections import Counter

def analyze_json(file_path):
    """Process JSON log file and generate statistics."""
    total_commands = 0
    found_commands = 0
    not_found_commands = 0
    command_counter = Counter()
    attack_types = {
        'sql_injection': 0,
        'xss': 0,
        'dir_traversal': 0,
        'csrf': 0,
        'rce': 0
    }

    try:
        with open(file_path, 'r') as file:
            logs = json.load(file)
            for entry in logs:
                total_commands += 1
                command = entry.get('command', '')
                status = entry.get('status', '')

                # Categorize commands by attack type
                if re.search(r"(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|--|#|\s+or\s+1=1)", command, re.IGNORECASE):
                    attack_types['sql_injection'] += 1
                elif re.search(r"<script.*?>.*?</script>|alert\(|document\.cookie", command, re.IGNORECASE):
                    attack_types['xss'] += 1
                elif re.search(r"(\.\./|\.\.\\)", command):  # Directory traversal patterns
                    attack_types['dir_traversal'] += 1
                elif re.search(r"(GET|POST)\s+/.*\?id=\d+", command, re.IGNORECASE):  # CSRF pattern: GET/POST requests with query params
                    attack_types['csrf'] += 1
                elif re.search(r"(eval|system|exec|popen|wget|curl)", command, re.IGNORECASE):  # Remote Code Execution
                    attack_types['rce'] += 1

                if status == 'found':
                    found_commands += 1
                    command_counter['Found'] += 1
                elif status == 'not found':
                    not_found_commands += 1
                    command_counter['Not Found'] += 1
                else:
                    command_counter['Other'] += 1

                # Track unique commands
                command_counter[command] += 1

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: The file '{file_path}' is not a valid JSON file.")
        return {}

    return {
        'total_commands': total_commands,
        'found_commands': found_commands,
        'not_found_commands': not_found_commands,
        'command_counter': command_counter,
        'attack_types': attack_types
    }

def analyze_log(file_path):
    """Process plain text log file and generate statistics."""
    total_commands = 0
    found_commands = 0
    not_found_commands = 0
    command_counter = Counter()
    attack_types = {
        'sql_injection': 0,
        'xss': 0,
        'dir_traversal': 0,
        'csrf': 0,
        'rce': 0
    }

    # Regex pattern to extract relevant parts of the log
    log_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}Z) \[HoneyPotSSHTransport,\d+,([\d\.]+)\] (CMD: .+)'
    not_found_pattern = r'Command not found: (.+)'
    found_pattern = r'Command found: (.+)'

    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Match log entries using regex
                match = re.search(log_pattern, line)
                if match:
                    timestamp, src_ip, command = match.groups()
                    total_commands += 1

                    # Categorize commands by attack type
                    if re.search(r"(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|--|#|\s+or\s+1=1)", command, re.IGNORECASE):
                        attack_types['sql_injection'] += 1
                    elif re.search(r"<script.*?>.*?</script>|alert\(|document\.cookie", command, re.IGNORECASE):
                        attack_types['xss'] += 1
                    elif re.search(r"(\.\./|\.\.\\)", command):  # Directory traversal patterns
                        attack_types['dir_traversal'] += 1
                    elif re.search(r"(GET|POST)\s+/.*\?id=\d+", command, re.IGNORECASE):  # CSRF pattern: GET/POST requests with query params
                        attack_types['csrf'] += 1
                    elif re.search(r"(eval|system|exec|popen|wget|curl)", command, re.IGNORECASE):  # Remote Code Execution
                        attack_types['rce'] += 1

                    # Check if the command was found or not
                    if re.search(not_found_pattern, line):
                        not_found_commands += 1
                        command_counter['Not Found'] += 1
                    elif re.search(found_pattern, line):
                        found_commands += 1
                        command_counter['Found'] += 1
                    else:
                        command_counter['Other'] += 1

                    # Track unique commands
                    command_counter[command] += 1

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        return {}

    return {
        'total_commands': total_commands,
        'found_commands': found_commands,
        'not_found_commands': not_found_commands,
        'command_counter': command_counter,
        'attack_types': attack_types
    }

def plot_attack_summary(attack_types):
    """Plot the attack type summary as a bar chart with labels."""
    # Define more professional names for the attack types
    attack_labels = ['SQL Injection', 'XSS', 'Directory Traversal', 'CSRF', 'Remote Code Execution ']
    
    # Get attack counts (in the same order as the labels)
    attack_counts = list(attack_types.values())

    # Create the bar chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(attack_labels, attack_counts, color=['red', 'blue', 'green', 'orange', 'purple'])

    # Add labels and title
    plt.xlabel('Attack Type')
    plt.ylabel('Number of Occurrences')
    plt.title('Attack Type Summary')
    plt.ylim(0, max(attack_counts) + 5)  # Add some space above the bars

    # Add the number labels on top of each bar
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 0.5, str(int(yval)), ha='center', va='bottom', fontweight='bold')

    plt.show()

def process_files(file_paths):
    """Process multiple files (JSON and log) and aggregate statistics."""
    total_stats = {
        'total_commands': 0,
        'found_commands': 0,
        'not_found_commands': 0,
        'command_counter': Counter(),
        'attack_types': {
            'sql_injection': 0,
            'xss': 0,
            'dir_traversal': 0,
            'csrf': 0,
            'rce': 0
        }
    }

    for file_path in file_paths:
        # Determine if the file is JSON or log
        if file_path.endswith('.json'):
            stats = analyze_json(file_path)
        elif file_path.endswith('.log'):
            stats = analyze_log(file_path)
        else:
            print(f"Skipping unsupported file type: {file_path}")
            continue

        # Aggregate results
        if stats:
            total_stats['total_commands'] += stats['total_commands']
            total_stats['found_commands'] += stats['found_commands']
            total_stats['not_found_commands'] += stats['not_found_commands']
            total_stats['command_counter'] += stats['command_counter']
            for attack_type in total_stats['attack_types']:
                total_stats['attack_types'][attack_type] += stats['attack_types'][attack_type]

    # Print out the aggregated statistics
    print(f"Total commands processed: {total_stats['total_commands']}")
    print(f"Commands found: {total_stats['found_commands']}")
    print(f"Commands not found: {total_stats['not_found_commands']}")
    print("Unique commands attempted:")
    for command, count in total_stats['command_counter'].items():
        print(f"  {command}: {count}")

    print("\nAttack Type Summary:")
    for attack_type, count in total_stats['attack_types'].items():
        print(f"  {attack_type}: {count}")

    # Plot the attack type summary
    plot_attack_summary(total_stats['attack_types'])

def main():
    """Main function to process multiple JSON and log files simultaneously."""
    # Hardcode file paths (adjust these paths as needed)
    file_paths = [
        "/Users/abdullah/cowrie/var/log/cowrie/cowrie.json", 
        "/Users/abdullah/cowrie/var/log/cowrie/dir_traversal_attacks.log", 
        "/Users/abdullah/cowrie/var/log/cowrie/sql_injections.log",
        "/Users/abdullah/cowrie/var/log/cowrie/csrf_attacks.log",
        "/Users/abdullah/cowrie/var/log/cowrie/rce_attacks.log",
        "/Users/abdullah/cowrie/var/log/cowrie/xss_attacks.log"
    ]

    # Process the files
    process_files(file_paths)

if __name__ == "__main__":
    main()