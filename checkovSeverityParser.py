import json
import re
import requests
from bs4 import BeautifulSoup

def update_error_levels_to_note(file_path):
    """Update all 'error' levels to 'note' in a SARIF file."""
    with open(file_path, 'r') as file:
        data = json.load(file)

    def update_levels(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == 'level' and value == 'error':
                    obj[key] = 'warning'
                elif isinstance(value, (dict, list)):
                    update_levels(value)
        elif isinstance(obj, list):
            for item in obj:
                update_levels(item)

    update_levels(data)

    updated_file_path = 'updated_' + file_path
    with open(updated_file_path, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"Updated SARIF file has been saved as {updated_file_path}.")



def update_links_in_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    pattern = r'https://docs\.prismacloud\.io/en/enterprise-edition/(.+)'
    replacement = r'https://github.com/hlxsites/prisma-cloud-docs/blob/main/docs/en/enterprise-edition/\1.adoc'

    def update_links(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    obj[key] = re.sub(pattern, replacement, value)
                else:
                    update_links(value)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = re.sub(pattern, replacement, item)
                else:
                    update_links(item)

    update_links(data)

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"Links in {file_path} have been updated and saved to {file_path}.")


def load_severities(severity_file_path):
    """Load the severities from the severities.json file into a dictionary."""
    with open(severity_file_path, 'r') as file:
        severity_data = json.load(file)
    severity_dict = {item['id']: item['severity'] for item in severity_data}
    return severity_dict

def update_levels_in_results(sarif_file_path, severity_dict):
    """Update levels in the SARIF file results based on severities from the dictionary."""
    with open(sarif_file_path, 'r') as file:
        data = json.load(file)
    updated = False

    for result in data.get('runs', [])[0].get('results', []):
        rule_id = result.get('ruleId', '')
 
        if rule_id in severity_dict:
            new_level = severity_dict[rule_id]
            current_level = result.get('level', '')
            if current_level != new_level:
                result['level'] = new_level
                updated = True
     #           print(f"Updated ruleId {rule_id} level from {current_level} to {new_level}")


    if updated:
        updated_file_path = 'final_' + sarif_file_path
        with open(updated_file_path, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Final updated SARIF file has been saved as {updated_file_path}.")
    else:
        print("No updates were necessary.")


def get_severity_from_guideline(helpUri):
    """Fetch the severity from the guideline URL."""
    try:
        response = requests.get(helpUri, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        severity_td = soup.find('td', text='Severity')
        if severity_td:
            severity_value = severity_td.find_next_sibling('td').text.strip().upper()
      #      print(f"{helpUri}: {severity_value}")
            if severity_value == 'LOW':
                return 'note'
            elif severity_value == 'MEDIUM':
                return 'warning'
            elif severity_value == 'HIGH':
                return 'error'
            elif severity_value == 'CRITICAL':
                return 'error'
            else:
                return 'note'
    except requests.RequestException as e:
    #    print(f"Error fetching guideline: {e}")
        if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
    #        print(f"Skipping 404 error for URL: {helpUri}")
            return 'note'
        else:
            return 'note'
    return 'note'



def update_links_in_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    pattern = r'https://docs\.prismacloud\.io/en/enterprise-edition/(.+)'
    replacement = r'https://github.com/hlxsites/prisma-cloud-docs/blob/main/docs/en/enterprise-edition/\1.adoc'

    def update_links(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    obj[key] = re.sub(pattern, replacement, value)
                else:
                    update_links(value)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = re.sub(pattern, replacement, item)
                else:
                    update_links(item)

    update_links(data)

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

    print(f"Links in {file_path} have been updated and saved to {file_path}.")

def update_severities_in_sarif(file_path, updated_file_path):
    """Update severities in a SARIF file based on guideline URLs and store them in a separate array."""
    with open(file_path, 'r') as file:
        data = json.load(file)

    severity_list = []
    total_rules = 0
    processed_rules = 0

    for run in data.get('runs', []):
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            total_rules += 1
            help_uri = rule.get('helpUri', '')
            rule_id = rule.get('id', 'unknown_id')
            if help_uri:
        #        print(f"Fetching severity for URL: {help_uri}")
                level = get_severity_from_guideline(help_uri)
                rule['defaultConfiguration']['level'] = level
        #        print(f"Updated rule {rule_id} to level: {level}")
                processed_rules += 1
                severity_list.append({"id": rule_id, "severity": level})

    print(f"Processed {processed_rules}/{total_rules} rules.")

    with open(updated_file_path, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Updated SARIF file has been saved as {updated_file_path}.")

    severity_file_path = 'severities.json'
    with open(severity_file_path, 'w') as severity_file:
        json.dump(severity_list, severity_file, indent=4)
    print(f"Severities have been saved in {severity_file_path}.")




file_path = 'results_sarif.sarif'  # Replace with your input file path
updated_file_path = 'updated_results_sarif.sarif'  # Replace with your output file path
result_file_path = 'result.sarif'
update_links_in_file(file_path)
update_error_levels_to_note(file_path)

# Process the SARIF file
update_severities_in_sarif(updated_file_path, result_file_path)

severity_file_path = 'severities.json'  # Replace with the path to severities.json

# Load the severity mappings
severity_dict = load_severities(severity_file_path)

# Update the SARIF file based on the loaded severities
update_levels_in_results(result_file_path, severity_dict)
