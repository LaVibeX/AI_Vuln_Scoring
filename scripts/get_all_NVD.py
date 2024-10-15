import requests
import json
import time

# Base URL of the API
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

# Function to get CVE information from NVD API
def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        cve_data = response.json()['vulnerabilities'][0]['cve']
        cve_data = parse_cve_item(cve_data)
        return {
            'CVE': cve_data['id'],
            'Description': cve_data['description'],
            'CWE': cve_data['weakness_description'],
            'Score': cve_data['primary_baseScore'],
            'Vector': cve_data['primary_vectorString'],
            'Secondary Score': cve_data['secondary_baseScore'],
            'Secondary Vector': cve_data['secondary_vectorString'],
        }
    else:
        raise Exception(f"Error fetching CVE: {response.status_code}")

def fetch_cve_data(results_per_page, start_index):
    params = {
        'resultsPerPage': results_per_page,
        'startIndex': start_index
    }
    response = requests.get(base_url, params=params)
    response.raise_for_status()  # will raise an error if the request failed
    return response.json()

# Function to flatten the nested structure and extract the required fields
def parse_cve_item(cve_item):
    cve_data = {
        'id': cve_item.get('id'),
        'sourceIdentifier': cve_item.get('sourceIdentifier'),
        'description': None,  # Default to None in case no English description is found
        'primary_baseScore': None,
        'primary_vectorString': None,
        'primary_source': None,
        'secondary_baseScore': None,
        'secondary_vectorString': None,
        'secondary_source': None,
        'weakness_description': None,
        'patch_url': None
    }
    
    # Descriptions
    descriptions = cve_item.get('descriptions', [])
    for desc in descriptions:
        if desc['lang'] == 'en':
            cve_data['description'] = desc['value']
            break
    
    # Metrics
    metrics = cve_item.get('metrics', {})
    cvss_v31_primary = next((metric for metric in metrics.get('cvssMetricV31', []) if metric.get('type') == 'Primary'), {})
    cvss_v31_secondary = next((metric for metric in metrics.get('cvssMetricV31', []) if metric.get('type') == 'Secondary'), {})
    
    if cvss_v31_primary:
        cvss_data_primary = cvss_v31_primary.get('cvssData', {})
        cve_data.update({
            'primary_vectorString': cvss_data_primary.get('vectorString'),
            'primary_baseScore': cvss_data_primary.get('baseScore'),
            'primary_source': cvss_v31_primary.get('source'),
        })
        
    if cvss_v31_secondary:
        cvss_data_secondary = cvss_v31_secondary.get('cvssData', {})
        cve_data.update({
            'secondary_vectorString': cvss_data_secondary.get('vectorString'),
            'secondary_baseScore': cvss_data_secondary.get('baseScore'),
            'secondary_source': cvss_v31_secondary.get('source')
        })
    
    # Weaknesses
    weaknesses = cve_item.get('weaknesses', [])
    if weaknesses:
        weakness = weaknesses[0].get('description', [])
        if weakness:
            cve_data['weakness_description'] = weakness[0].get('value')
    
    # References with Patch tag
    references = cve_item.get('references', [])
    for ref in references:
        if 'Patch' in ref.get('tags', []):
            cve_data['patch_url'] = ref.get('url')
            break
    
    return cve_data

# Function to iterate over pages and collect data
def iterate_pages_and_save():
    results_per_page = 2000  # Set to the maximum allowable limit
    start_index = 0

    # Fetch initial data to get the total results
    data = fetch_cve_data(results_per_page, start_index)
    total_results = data['totalResults']

    # Calculate total pages
    total_pages = (total_results + results_per_page - 1) // results_per_page  # ceiling division
    
    all_cve_data = []

    try:
        for page in range(total_pages):
            print(f"Fetching page {page + 1}/{total_pages}")
            start_index = page * results_per_page
            
            for attempt in range(5):  # Retry up to 5 times
                try:
                    data = fetch_cve_data(results_per_page, start_index)
                    vulnerabilities = data.get('vulnerabilities', [])
                    for item in vulnerabilities:
                        cve_item = item.get('cve', {})
                        parsed_cve_item = parse_cve_item(cve_item)
                        all_cve_data.append(parsed_cve_item)
                    break   # If request is successful, break out of the retry loop
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 403:
                        print(f"403 error encountered. Waiting before retrying... Attempt {attempt + 1}")
                        time.sleep(5 * (2 ** attempt))  # Exponential backoff
                    else:
                        raise e  # Re-raise if it's not a 403 error
                
            else:
                print("Max retries reached. Exiting...")
                return

    except Exception as e:
        print(f"An error occurred: {e}")
    
    # Save data to a JSON file
    with open("NVD_cves.json", 'w') as outfile:
        json.dump(all_cve_data, outfile, indent=2)

def main():
    iterate_pages_and_save()

if __name__ == "__main__":
    main()