import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
from streamlit_tags import st_tags
from streamlit_elements import elements, mui
import datetime
import numpy as np

from backend import get_evaluation, load_dataframe,get_accuracy, cve_evaluator, all_model_evaluator,create_chart_data

# Define the DataFrame mapping
dataframe_mappings = {
    "NVD Primary Score": "./datasets/NVD1_df.csv",
    "NVD Secondary Score": "./datasets/NVD2_df.csv",
    "RedHat": "./datasets/RedHat_df.csv",
    "GitHub": "./datasets/GitHub_df.csv",
    "Microsoft": "./datasets/MSRC_df.csv"
}

model_mapping = {
    "Llama-8b": "llama-3.1-8b-instruct",
    "GPT-4o-mini": "gpt-4o-mini",
    "GPT-4o": "gpt-4o",
    "Chat-Rag": "chat-rag"
}

accuracy_mapping = {
    'Based on Severity Level¹': 1,
    'Based on Action needed²': 2,
    'Threshold³': 3
}
# Create tabs
tab1, tab2, tab3 = st.tabs(["Evaluation Dashboard", "CSV File Reader", "CVE Evaluator"])

# Tab 1: Evaluation Dashboard
with tab1:
    with elements("input_section"):
        with mui.Box(sx={"padding": "1em", "backgroundColor": "#f0f0f0"}):
            st.title("Evaluation Dashboard")
            st.write("Provide model, DataFrame options, and other parameters for evaluation.")

            # Option to upload CSV file or select model
            st.subheader("AI Model")
            model_choice = st.selectbox("Select Model", list(model_mapping.keys()))

            selected_model = model_mapping[model_choice]

            # Option to upload CSV file (this is optional, depending on the workflow)
            uploaded_file = st.file_uploader("Upload Model Score CSV (optional)", type=["csv"])

            # Logic to load the correct DataFrame based on model selection or CSV file
            if uploaded_file is not None:
                model_df = pd.read_csv(uploaded_file)
                st.success(f"DataFrame loaded from uploaded file: {uploaded_file.name}")
            else:
                model_df, model_name = load_dataframe(selected_model)
                if model_df is not None:
                    st.success(f"DataFrame loaded for model: {model_name}")
                else:
                    st.error(f"No DataFrame available for the {selected_model}")

            # DataFrame radio options
            st.subheader("Source Scores")
            dataframe_choice = st.radio("Select DataFrame", list(dataframe_mappings.keys()))

            # Tags input using streamlit-tags
            st.subheader("Tags")
            notes = st_tags(
                label="Add your tags:",
                text="Press enter to add more",
                maxtags=10
            )

            #Accuracy
            st.subheader("Accuracy Measurement")
            accuracy_type = st.radio("Select Type", list(accuracy_mapping.keys()))
            
            disable_slider= True

            if accuracy_type == 'Threshold³':
                disable_slider= False
                
            threshold = st.slider("Accuracy Tolerance", 0.0, 5.0, 0.5,0.1,disabled=disable_slider)
            st.caption("1. Same Severity Level")
            st.caption("2. Action needed: matching score above 7.0 between original score and LLM score")
            st.caption("3. User-defined acceptable accuracy")
            # Score Column
            st.subheader("Score Column")
            cvss_score = st.toggle("Use CVSS Calculated Score based on LLM vector",value=True)           

    with elements("output_section"):
        with mui.Box(sx={"padding": "1em", "backgroundColor": "#e0e0e0"}):
            # Button to trigger evaluation
            if st.button("Evaluate"):
                # Load the DataFrame based on selection or CSV file
                dataframe = pd.read_csv(dataframe_mappings[dataframe_choice])

                # Call the evaluation function
                result_df, fig = get_evaluation(model_df, dataframe, notes,cvss_score, accuracy_mapping[accuracy_type], threshold)

                # Display the results
                st.subheader("Resulting DataFrame")
                st.write(result_df)
                # Split the layout into two columns
                col1, col2 = st.columns([1, 2])  # Adjust width ratio as needed

                with col1:
                    st.subheader("Accuracy Pie Chart")
                    st.pyplot(fig)

                with col2:
                    st.subheader("Statistics")
                    # Display descriptive statistics
                    st.write("Descriptive Statistics:")
                    st.write(result_df.describe())

# Tab 2: CSV File Reader and Statistics
with tab2:
    st.title("CSV File Reader")

    uploaded_file = st.file_uploader("Upload a CSV file to analyze", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        # Split the layout into two columns
        col1, col2 = st.columns([1, 2])  # Adjust width ratio as needed

        with col1:
            _, fig = get_accuracy(df)
            st.subheader("Accuracy Pie Chart")
            st.pyplot(fig)

        with col2:
            st.subheader("Statistics")
            # Display descriptive statistics
            st.write("Descriptive Statistics:")
            st.write(df.describe())

        st.subheader("DataFrame")
        st.write(df)

    else:
        st.warning("Please upload a CSV file to analyze.")

# Tab 3: CVE Evaluator
with tab3:
    st.title("CVE Evaluator")

    # Option to upload CSV file or select model
    st.subheader("AI Model")
    new_model_list = ["All"] + list(model_mapping.keys()) 
    model_choice = st.selectbox("Select Model", new_model_list, key=2)
    

    # Input for CVE ID
    cve_id = st.text_input("Insert CVE", placeholder="CVE-2023-2134")

    if st.button("Evaluate CVE"):
        if cve_id:
            results = []
            try:
                # Call the CVE evaluator function
                if model_choice != "All":
                    model_choice_evaluator=model_mapping[model_choice]
                    nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector = cve_evaluator(cve_id, model_choice_evaluator)
                    create_chart_data(model_choice, nvd_score, llm_score, calculated_score_llm,nvd_vector,llm_vector)
                else:
                    all_model_evaluator(cve_id,model_mapping.values())

            except Exception as e:
                st.write(f"Error evaluating CVE: {e}")