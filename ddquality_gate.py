import requests
import sys
import argparse
import os


def sum_severity(findings):
    severity = [0, 0, 0, 0]  # Critical, High, Medium, Low
    print (findings)
    for finding in findings:
        if finding["severity"] == "Critical":
            severity[0] += 1
        elif finding["severity"] == "High":
            severity[1] += 1
        elif finding["severity"] == "Medium":
            severity[2] += 1
        elif finding["severity"] == "Low":
            severity[3] += 1
    return severity

def quality_gate(severity, critical=0, high=0, medium=0, low=0):
    gateway = [critical, high, medium, low]  # Quality Gate by severity
    health = True
    for i in range(4):
        if severity[i] > int(gateway[i]):
            health = False
    print(f"Critical: {severity[0]} High: {severity[1]} Medium: {severity[2]} Low: {severity[3]}")
    print(f"Quality Gate Status: {'Success' if health else 'Failed'}")
    print(f"Detail DefectDojo Engagement Link: {host}engagement/{engagement_id}")
    if not health:
        send_slack_notification(f"Quality Gate Failed: {engagement_name} Get detail {host}engagement/{engagement_id}")
    sys.exit(0 if health else 1)

def send_slack_notification(message):
    payload = {'text': message}
    try:
        response = requests.post(slack, json=payload)
        print(response.text)
        response.raise_for_status()
        print("Slack notification sent successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Slack notification: {e}")


def get_tests(engagement_id):
    test_rq = host + 'api/v2/tests/'
    payload = {'engagement': engagement_id, 'o': '-updated', 'limit': 1000}
    request = requests.get(test_rq, params=payload, headers=headers)
    print(request.text)
    print ([test['id'] for test in request.json()['results']])
    return [test['id'] for test in request.json()['results']]

def get_findings(test_id):
    findings_rq = host + 'api/v2/findings/'
    payload = {'test': test_id, 'false_p': 'false', 'limit': 10000000, 'is_mitigated': 'false'}
    request = requests.get(findings_rq, params=payload, headers=headers)
    print(request.text)
    return request.json()['results']

def get_engagement_id_by_name(engagement_name):
    engagements_rq = host + 'api/v2/engagements/'
    payload = {'name': engagement_name}
    request = requests.get(engagements_rq, params=payload, headers=headers)
    print(request.text)
    engagements = request.json()['results']
    
    if not engagements:
        print(f"No engagement found with name: {engagement_name}")
        sys.exit(1)
    
    return engagements[0]['id']


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DefectDojo report uploader')
    parser.add_argument('--engagement', help="Engagement name", required=True)
    parser.add_argument('--critical', help="Quality Gate Critical Warnings Level", type=int, default=0, required=False)
    parser.add_argument('--high', help="Quality Gate High Warnings Level", type=int, default=0, required=False)
    parser.add_argument('--medium', help="Quality Gate Medium Warnings Level", type=int, default=0, required=False)
    parser.add_argument('--low', help="Quality Gate Low Warnings Level", type=int, default=0, required=False)
    parser.add_argument('--token', help="API Token", required=True)
    parser.add_argument('--host', help="DOJO host", required=True)
    parser.add_argument('--slack', help="Slack Token", required=True)
    
    args = parser.parse_args()
    engagement_name = args.engagement
    critical = args.critical
    high = args.high
    medium = args.medium
    low = args.low
    token = args.token
    slack = args.slack
    host = args.host
 


    headers = {'Authorization': 'Token ' + token, 'accept': 'application/json'}
    engagement_id = get_engagement_id_by_name(engagement_name)
    test_ids = get_tests(engagement_id)
    all_findings = []
    for test_id in test_ids:
        all_findings.extend(get_findings(test_id))
    severity = sum_severity(all_findings)
    quality_gate(severity, critical, high, medium, low)
