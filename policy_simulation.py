import csv
import json
import sys
from collections import defaultdict
from policy_evaluator import evaluate_request

# Defines the static path to the old policy for comparison.
OLD_POLICY_PATH = 'policies/old_policy.json'

def run_simulation(log_file='access_logs.csv', new_policy_path=None):
    """
    Compares the outcomes of old and new policies against access logs
    and generates an impact report.
    """
    if not new_policy_path:
        print("Error: Path to the new policy JSON file is required.")
        sys.exit(1)

    # Load both the old and new policy files.
    try:
        with open(OLD_POLICY_PATH, 'r') as f:
            old_policy = json.load(f)
        with open(new_policy_path, 'r') as f:
            new_policy = json.load(f)
    except FileNotFoundError as e:
        print(f"Error loading policy file: {e}")
        sys.exit(1)


    affected_users = defaultdict(list)

    # Process each row in the access log file.
    with open(log_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            request_params = {
                'role': row['role'],
                'department': row['department'],
                'resource': row['resource'],
                'action': row['action']
            }

            old_dec, old_reason = evaluate_request(old_policy, **request_params)
            new_dec, new_reason = evaluate_request(new_policy, **request_params)

            if new_dec != old_dec:
                change_type = f"{old_dec} -> {new_dec}"
                # The 'why' variable correctly captures the specific reason from the new policy file.
                why = new_reason if new_dec == 'denied' else "Permitted by new policy rule."
                affected_users[row['user_id']].append({
                    'resource': row['resource'],
                    'action': row['action'],
                    'change': change_type,
                    'why': why
                })
    
    write_report(affected_users)

def write_report(affected_users):
    """Writes the simulation results to simulation_result.txt in the specified format."""
    denied_users = {k: [c for c in v if '-> denied' in c['change']] for k, v in affected_users.items() if any('-> denied' in c['change'] for c in v)}
    
    with open('simulation_result.txt', 'w') as out_f:
        out_f.write("## 📜 Policy Impact Analysis\n\n")
        out_f.write("### If I roll out this new policy, who is likely to get denied access and why?\n")

        if not denied_users:
            out_f.write("No users are likely to be newly denied access.\n")
        else:
            for user_id, changes in denied_users.items():
                out_f.write(f" - User {user_id}:\n")
                for change in changes:
                    out_f.write(f"   - For {change['action']} on {change['resource']}: {change['why']}\n")

        # You can still include a section for newly permitted users if you wish.
        permitted_users = {k: [c for c in v if '-> permitted' in c['change']] for k, v in affected_users.items() if any('-> permitted' in c['change'] for c in v)}
        if permitted_users:
            out_f.write("\n### Who is likely to gain access?\n")
            for user_id, changes in permitted_users.items():
                out_f.write(f" - User {user_id} will newly gain access for:\n")
                for change in changes:
                    out_f.write(f"   - {change['action']} on {change['resource']}\n")

# This block makes the script runnable from the command line.
if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_simulation(new_policy_path=sys.argv[1])
    else:
        print(f"Usage: python {sys.argv[0]} <path_to_new_policy.json>")
        sys.exit(1)