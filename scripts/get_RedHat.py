import requests
import json

def fetch_redhat_cves(per_page=1000):
    page = 1
    cves = []

    while True:
        print(f"Working on page: {page}")
        url = f'https://access.redhat.com/labs/securitydataapi/cve.json?per_page={per_page}&page={page}'
        
        try:
            response = requests.get(url)
            response.raise_for_status()  # Check if request was successful
        except requests.RequestException as e:
            print(f"An error occurred while making the request: {e}")
            break

        try:
            data = response.json()  # Attempt to parse JSON response
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            break

        # Process the data based on its type
        if isinstance(data, list):
            cves.extend(data)
            if not data:
                break  # Stop if no more data
        elif isinstance(data, dict) and 'data' in data:
            cves.extend(data['data'])
            if not data['data']:
                break  # Stop if no more data
        else:
            print("Unexpected API response format")
            break

        page += 1

    return cves

def save_cves_to_file(cves, file_name='RedHat_cves.json'):
    with open(file_name, 'w') as f:
        json.dump(cves, f, indent=2)
    print(f"Data saved to {file_name}")

def main():
    # Fetch the Red Hat CVEs
    cves = fetch_redhat_cves()

    # Save them to a file
    if cves:
        save_cves_to_file(cves)
    else:
        print("No CVEs found to save.")

if __name__ == "__main__":
    main()