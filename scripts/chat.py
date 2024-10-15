import os
import requests
import json
import argparse
import time
from dotenv import load_dotenv
from openai import OpenAI



payload_defaults={
    "system message": {
                "role": "system",
                "content": "You are an expert in CVSS 3.1 scoring. Provide the correct base score and a valid CVSS 3.1 vector. Ensure the vector is complete, well-formed, and adheres to the CVSS 3.1 standard."
            },
    "max_tokens": 512,
    "temperature": 0.01,
    "top_p": 0.9,
    "n": 1,
    "timeout":30
}

# Define the API endpoint or base_url
def get_client(model):    
    # Check if the model is a Meta LLaMA model
    load_dotenv()
    if "gpt" in model:
        api_key = os.getenv('OPENAI_API_KEY')
        client = OpenAI(api_key=api_key)  # Use default OpenAI client
    else:
        api_key = os.getenv('GPT_TOKEN')
        base_url = os.getenv('MODEL_URL1')  # Use custom base_url for Meta LLaMA models
        client = OpenAI(api_key=api_key, base_url=base_url)
    
    return client

# Example CVE
cve_ex = 'CVE-2022-41243'
description_ex = 'Jenkins SmallTest Plugin 1.0.4 does not perform hostname validation...'
cwe_ex = 'CWE-295'

# Template for the content
def create_message(cve, description, cwe):
    return {
        "role": "user",
        "content": f"CVE: {cve} Description: {description} CWE: {cwe}"
    }

# Function to create the payload
def create_payload(cve, description, cwe):
    example_message = create_message(cve_ex, description_ex, cwe_ex)
    user_message = create_message(cve, description, cwe)

    message = [
            payload_defaults["system message"],
            example_message,
            {
                "role": "assistant",
                "content": "Base Score: 8.1\nVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            user_message
        ]

    return message

def ask_bot(model, cve, description, cwe, retries=7, base_delay=1):
    client = get_client(model)  # Get the appropriate client based on the model
    message = create_payload(cve, description, cwe)  # Generate payload externally
    
    for attempt in range(retries):
        try:
            # Make the request
            response = client.chat.completions.create(
                messages=message,
                model=model,
                max_tokens=payload_defaults["max_tokens"],
                temperature=payload_defaults["temperature"],
                top_p=payload_defaults["top_p"],
                n=payload_defaults["n"],
                timeout=payload_defaults["timeout"]
            )

            # Extract the assistant's reply
            content = response.choices[0].message.content
            lines = content.split('\n')

            # Check if we have at least two lines for score and vector
            if len(lines) < 2:
                raise ValueError("Incomplete response: missing CVSS score or vector")

            # Extract CVSS Score and Vector from the response
            cvss_score = lines[0].replace("Base Score: ", "").strip()
            vector = lines[1].replace("Vector: ", "").strip()

            return cvss_score, vector, None  # No error

        except requests.exceptions.HTTPError as e:
            # Handle rate limiting (429) or other server errors (e.g., 403)
            if e.response.status_code == 429:
                wait_time = base_delay * (2 ** attempt)
                time.sleep(wait_time)
            elif e.response.status_code == 403:
                wait_time = 5 * (2 ** attempt)
                time.sleep(wait_time)
            else:
                return None, None, e.response.status_code  # Return the error code on critical errors

        except requests.RequestException:
            # Handle connection errors, etc.
            return None, None, "CONNECTION_ERROR"  # Return a custom error code for connection issues

        except KeyError:
            return None, None, "KEY_ERROR"

        except ValueError as e:
            # Handle incomplete or malformed response
            print(f"Error: {e}")
            return None, None, "MALFORMED_RESPONSE"

    return None, None, "MAX_RETRIES"  # Max retries reached, return this error code

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Send vulnerability details to the API.')
    parser.add_argument('model', type=str, help='AI model to use')
    parser.add_argument('cve', type=str, help='The CVE identifier')
    parser.add_argument('description', type=str, help='The vulnerability description')
    parser.add_argument('cwe', type=str, help='The CWE identifier')
    args = parser.parse_args()
    
    # Call the function to send the request and unpack the result
    score, vector, error = ask_bot(args.model, args.cve, args.description, args.cwe)

    # Check if the function returned valid results
    if score is not None and vector is not None:
        print(f"CVSS Score: {score}")
        print(f"Vector: {vector}")
    else:
        print(f"Failed to retrieve CVSS score and vector. Error: {error}")

if __name__ == '__main__':
    main()
