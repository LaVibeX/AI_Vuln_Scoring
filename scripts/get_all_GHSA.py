import requests
import json
import os

def get_token():
    # Access the token from the environment
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN_LLM')

    # Use the token in your script
    if GITHUB_TOKEN:
        print("API token retrieved successfully.")
        return GITHUB_TOKEN
    else:
        raise Exception("API token not found. Please set the 'GITHUB_TOKEN_LLM' environment variable.")

def create_headers(token):
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

# Define the GraphQL query with pagination
query_template = """
query ($cursor: String) {
  securityAdvisories(first: 100, after: $cursor) {
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      identifiers {
        type
        value
      }
      description
      origin
      cwes(first: 10) {
        nodes {
          cweId
        }
      }
      vulnerabilities(first: 10) {
        nodes {
          package {
            name
          }
          severity
          advisory {
            cvss {
              score
              vectorString
            }
          }
        }
      }
    }
  }
}
"""

def run_query(query, variables, headers):
    response = requests.post('https://api.github.com/graphql', json={'query': query, 'variables': variables}, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Query failed to run: {response.status_code}. {response.text}")

def parse_advisory(advisory):
    # Extract CVE identifier
    cve_id = next((identifier['value'] for identifier in advisory['identifiers'] if identifier['type'] == 'CVE'), None)
    description = advisory.get('description')
    
    # Extract CWEs
    cwes = [cwe['cweId'] for cwe in advisory.get('cwes', {}).get('nodes', [])]
    
    vulnerabilities = advisory.get('vulnerabilities', {}).get('nodes', [])
    parsed_vulnerabilities = []
    for vuln in vulnerabilities:
        package_name = vuln.get('package', {}).get('name')
        severity = vuln.get('severity')
        cvss = vuln.get('advisory', {}).get('cvss', {})
        cvss_score = cvss.get('score')
        cvss_vector = cvss.get('vectorString')

        parsed_vulnerabilities.append({
            'cve_id': cve_id,
            'description': description,
            'cwes': cwes,
            'package_name': package_name,
            'severity': severity,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector
        })

    return parsed_vulnerabilities

def get_all_pages(headers):
    all_advisories = []
    cursor = None
    page_count = 0

    # Loop through all available pages
    while True:
        variables = {"cursor": cursor}
        result = run_query(query_template, variables, headers)
        advisories = result['data']['securityAdvisories']['nodes']
        for advisory in advisories:
            parsed_advisories = parse_advisory(advisory)
            all_advisories.extend(parsed_advisories)
        
        page_info = result['data']['securityAdvisories']['pageInfo']
        cursor = page_info['endCursor']
        if not page_info['hasNextPage']:
            break
        
        page_count += 1
        print(f"Processed page {page_count}")

    return all_advisories

def main():
    try:
        # Get the GitHub token and set up headers
        token = get_token()
        headers = create_headers(token)
        
        # Fetch advisories
        advisories = get_all_pages(headers)

        # Save the advisories to a JSON file
        with open("GHSA_cves.json", 'w') as outfile:
            json.dump(advisories, outfile, indent=2)

        print("Data saved to GHSA_cves.json")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()