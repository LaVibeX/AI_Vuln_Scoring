import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import datetime
import numpy as np
from get_all_NVD import get_cve_info
from chat import ask_bot
from cvss import CVSS3

#CVSS Calculator
def cvss_calculator(vector):
    try:
        cvss = CVSS3(vector)
        return cvss.scores()[0]
    except:
        return None

def cve_evaluator(cve_id, model):
    # Step 1: Get CVE information from NVD API
    nvd_score = 0.0
    llm_score = 0.0
    calculated_score_llm = 0.0
    nvd_vector = 0.0
    llm_vector = 0.0

    try:
        cve_info = get_cve_info(cve_id)
        score, vector, error = ask_bot(model, cve_info['CVE'], cve_info['Description'], cve_info['CWE'])
    except Exception as e:
        return nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector
    
    if vector is not None:
        cve_info['Calculated Score LLM'] = cvss_calculator(vector)
    else:
        cve_info['Calculated Score LLM'] = None

    # Step 3: Check if primary Score is valid, if not, use Secondary Score
    nvd_score = float(cve_info['Score']) if cve_info['Score'] is not None else float(cve_info['Secondary Score']) if cve_info['Secondary Score'] is not None else 0.0
    llm_score = float(score) if score is not None else 0.0  # Default to 0 if not available
    calculated_score_llm = float(cve_info['Calculated Score LLM']) if cve_info['Calculated Score LLM'] is not None else 0.0
    nvd_vector= cve_info['Vector'] if cve_info['Vector'] is not None else cve_info['Secondary Vector']
    llm_vector = vector
    return nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector  # Return scores for further processing

def create_chart_data(model_name, nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector):
    # Prepare DataFrame for scores
    data = {
        'NVD Score': nvd_score,
        'LLM Score': llm_score,
        'Calculated Score LLM': calculated_score_llm,
        'NVD Vector': nvd_vector,
        'LLM Vector': llm_vector
    }
    chart_data = pd.DataFrame(data, index=[model_name])
    st.dataframe(chart_data)
    # Drop the specified columns
    chart_data = chart_data.drop(columns=['NVD Vector', 'LLM Vector'])
    # Display the bar chart using Streamlit
    st.bar_chart(chart_data, stack=False)

def all_model_evaluator(cve_id, model_list):
    results = []

    # Run cve_evaluator for every model in the list
    for model in model_list:
        nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector = cve_evaluator(cve_id, model)
        model_name = model  # You can adjust this if you have a different name for models
        results.append((model_name, nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector))

    # Create a DataFrame from the results
    results_df = pd.DataFrame(results, columns=['Model Name', 'NVD Score', 'LLM Score', 'Calculated Score LLM', 'NVD Vector', 'LLM Vector'])

    # Set the 'Model Name' as the index for easier plotting
    results_df.set_index('Model Name', inplace=True)

    # Display the DataFrame
    st.dataframe(results_df)
    # Drop the specified columns
    results_df = results_df.drop(columns=['NVD Vector', 'LLM Vector'])
    # Display a single bar chart for all models
    st.bar_chart(results_df, height=400, stack=False)

    return results_df  # You can return results_df or modify as needed

# Load DataFrame from CSV file or model selection
def load_dataframe(model):
    file_list = [f for f in os.listdir("./model_scores") if model in f]
    if file_list:
        file_path = os.path.join("./model_scores", file_list[0])
        df = pd.read_csv(file_path)
        return df, model
    else:
        return None, model
        
def load_existing_csv(csv_file):
    """Load DataFrame from CSV if it exists and is not empty."""
    if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
        try:
            results_df = pd.read_csv(csv_file)
            if not results_df.empty:
                return results_df
            else:
                print("CSV file is empty.")
                return pd.DataFrame()
        except pd.errors.EmptyDataError:
            print("CSV file exists but is empty.")
            return pd.DataFrame()
    else:
        print("CSV file not found or is empty.")
        return pd.DataFrame()

def merge(model,dataframe):
    results_df = model.merge(dataframe[['CVE', 'Score', 'Vector']], on='CVE', how='inner')
    results_df = results_df.drop_duplicates(subset=['CVE'], keep='first')
    return results_df

# Define function to categorize CVSS scores
def get_cvss_category(score):
    if score == 0.0:
        return 'None'
    elif 0.1 <= score <= 3.9:
        return 'Low'
    elif 4.0 <= score <= 6.9:
        return 'Medium'
    elif 7.0 <= score <= 8.9:
        return 'High'
    elif 9.0 <= score <= 10.0:
        return 'Critical'
    else:
        return 'Invalid'

# Function to compare CVSS strings
def compare_vector_columns(df, col1, col2):
    def compare_vector_strings(vector1, vector2):
        vector1 = str(vector1) if pd.notnull(vector1) else ''
        vector2 = str(vector2) if pd.notnull(vector2) else ''
        components1 = vector1.split('/')
        components2 = vector2.split('/')
        differences = [f"{comp1} != {comp2}" for comp1, comp2 in zip(components1, components2) if comp1 != comp2]
        return ','.join(differences) if differences else '0 diff'
    df['vector_diff'] = df.apply(lambda row: compare_vector_strings(row[col1], row[col2]), axis=1)
    return df

def log_results(df, log, mean_deviation, mean_percentage_deviation, accuracy, log_file='log.txt'):
    log_entry = (
        f"\nInnerJoin Rows: {df.shape[0]}\n"
        f"Mean Deviation: {mean_deviation}\n"
        f"Mean Percentage Deviation: {mean_percentage_deviation:.2f}%\n"
        f"Accuracy within same Severity Level: {accuracy:.2f}%\n\n"
    )
    print(log_entry)
    log += log_entry
    # with open(log_file, 'a') as file:
    #     file.write(log)

def get_accuracy(df):
    accuracy = (df['Accurate'].sum() / len(df)) * 100
    fig, ax = plt.subplots()
    ax.pie([accuracy, 100 - accuracy], labels=['Correct', 'Incorrect'], autopct='%1.1f%%', colors=['#8BD3E6', '#FF6D6A'])
    ax.set_title("Accuracy Distribution")
    return accuracy,fig

def accuracy_based_on_severity(df):
    df['Accurate'] = df['Original_Category'] == df['LLM_Category']
    return df

def accuracy_based_on_action(df, original_score_column, llm_score_column):
    # Check if both original and LLM scores are greater than or equal to 7 (high/critical)
    high_accurate = (df[original_score_column] >= 7) & (df[llm_score_column] >= 7)
    # Check if both original and LLM scores are less than 7 (low/medium)
    low_accurate = (df[original_score_column] < 7) & (df[llm_score_column] < 7)
    # Mark as accurate if either condition is met
    df['Accurate'] = high_accurate | low_accurate
    return df

def accuracy_based_on_threshold(df, original_score_column, llm_score_column, threshold):
    # Calculate lower and upper bounds based on the original score and the threshold
    lower_bound = df[original_score_column] - threshold
    upper_bound = df[original_score_column] + threshold

    # Check if the LLM score is within the range (lower_bound, upper_bound)
    df['Accurate'] = (df[llm_score_column] >= lower_bound) & (df[llm_score_column] <= upper_bound)

    return df

def define_accuracy(acc_type, threshold, df, original_score_column, llm_score_column, ):
    if acc_type == 1:
        df= accuracy_based_on_severity(df)
    elif acc_type == 2:
        df= accuracy_based_on_action(df, original_score_column, llm_score_column)
    elif acc_type == 3:
        accuracy_based_on_threshold(df, original_score_column, llm_score_column, threshold)
    return df


def evaluate_score_accuracy(log, df, original_score_column, llm_score_column, acc_type, th):

    df[original_score_column] = pd.to_numeric(df[original_score_column], errors='coerce')
    df[llm_score_column] = pd.to_numeric(df[llm_score_column], errors='coerce')

    df['Deviation'] = abs(df[original_score_column] - df[llm_score_column])
    df['Percentage Deviation'] = (df['Deviation'] / df[original_score_column]) * 100
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    mean_deviation = df['Deviation'].mean()
    mean_percentage_deviation = df['Percentage Deviation'].mean()
    df['Original_Category'] = df[original_score_column].apply(get_cvss_category)
    df['LLM_Category'] = df[llm_score_column].apply(get_cvss_category)
    
    #Depending on the accuracy type change accuracy functions

    df = define_accuracy(acc_type, th, df, original_score_column, llm_score_column)
    
    accuracy, fig = get_accuracy(df)
    log_results(df, log, mean_deviation, mean_percentage_deviation, accuracy)
    
    return df, fig

def get_evaluation(model, dataframe, notes, calculated_score, acc_type ,th):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"Log Time: {current_time}\nModel: {model}\nDataFrame Rows: {dataframe.shape[0]}\nNotes: {notes}"
    
    results = merge(model, dataframe)

    if calculated_score:
        llm_score_col = 'Calculated_Score_LLM'
    else: 
        llm_score_col= 'Score_LLM'
    
    results = compare_vector_columns(results, 'Vector_LLM', 'Vector')
    evaluation, fig = evaluate_score_accuracy(log, results, 'Score', llm_score_col, acc_type, th)
    return evaluation, fig



