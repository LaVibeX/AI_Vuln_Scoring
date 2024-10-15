import tiktoken  # Make sure you have tiktoken installed via pip install tiktoken

# Global variable to keep track of the overall total cost
overall_total_cost = 0

# Dictionary to store results for each CVE
cve_results = {}

# Example CVE
cve_ex = 'CVE-2020-27829'
description_ex = 'A heap based buffer overflow in coders/tiff.c may result in program crash and denial of service in ImageMagick before 7.0.10-45.'
cwe_ex = 'CWE-122'

# Template for the content
def create_message(cve, description, cwe):
    return {
        "role": "user",
        "content": f"CVE: {cve} Description: {description} CWE: {cwe}"
    }

# Function to count tokens more accurately using tiktoken
def count_tokens(messages):
    encoding = tiktoken.encoding_for_model("gpt-4o")  # Replace with your model name
    total_tokens = sum([len(encoding.encode(msg['content'])) for msg in messages])
    return total_tokens

# Function to create the payload and calculate token counts
def create_payload_and_calculate_tokens(cve, description, cwe, price_per_1000_input=0.00014, price_per_1000_output=0.0006):

    example_message = create_message(cve_ex, description_ex, cwe_ex)
    user_message = create_message(cve, description, cwe)
    # example_message,
    # {
    #     "role": "assistant",
    #     "content": "Base Score: 8.1\nVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    # },

    message = [
            {
                "role": "system",
                "content": "You are an expert in CVSS 3.1 scoring. Provide the correct base score and a valid CVSS 3.1 vector. Ensure the vector is complete, well-formed, and adheres to the CVSS 3.1 standard."
            },
            user_message
        ]
    
    # Example assistant response (simulated)
    assistant_response = "Base Score: 8.1\nVector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # Use tiktoken to calculate the number of tokens
    input_tokens = count_tokens(message)
    output_tokens = len(tiktoken.encoding_for_model("gpt-4o").encode(assistant_response))

    # Store results in the cve_results dictionary
    cve_results[cve] = {
        "input": message,
        "output": assistant_response,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens
    }
    return cve_results, input_tokens,output_tokens

# Function to calculate the total cost for each model
def calculate_total_cost_per_model(total_input_tokens,total_output_tokens, model_info):
    for model_name, prices in model_info.items():
        price_per_1000_input = prices['input_price']
        price_per_1000_output = prices['output_price']
        
        total_input_cost = (total_input_tokens / 1000) * price_per_1000_input
        total_output_cost = (total_output_tokens / 1000) * price_per_1000_output
        total_cost = total_input_cost + total_output_cost
        
        print(f"Total cost for {model_name}: €{total_cost:.6f}")


def main():
    result, cost = create_payload_and_calculate_tokens(cve_ex, description_ex, cwe_ex)
    print(result)
    print(f"Total Cost: {cost}")

if __name__ == '__main__':
    main()