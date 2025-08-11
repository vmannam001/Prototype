def evaluate_request(policy, role, department, resource, action):
    """
    Evaluates an access request against a loaded policy object.

    Args:
        policy (dict): The loaded policy JSON.
        role (str): The user's role.
        department (str): The user's department.
        resource (str): The requested resource.
        action (str): The action being performed.

    Returns:
        tuple: A (decision, reason) tuple.
    """
    # Create a dictionary of the request attributes for easy comparison
    request_details = {
        'role': role,
        'department': department,
        'resource': resource,
        'action': action
    }

    # Find the first rule that matches the request
    for rule in policy.get('rules', []):
        conditions = rule.get('conditions', {})
        match = True
        for key, value in conditions.items():
            if request_details.get(key) != value:
                match = False
                break
        
        if match:
            return rule['decision'], rule['reason']

    # Default decision if no rules match
    return 'denied', 'Denied: No matching rule found.'