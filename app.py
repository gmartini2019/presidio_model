from fastapi import FastAPI, File, UploadFile
from io import StringIO
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from typing import List, Optional, Dict, Union, Iterator, Iterable
import collections
from dataclasses import dataclass
import pprint
from collections import defaultdict
import pandas as pd
from presidio_analyzer import AnalyzerEngine, PatternRecognizer
from presidio_analyzer import AnalyzerEngine, BatchAnalyzerEngine, RecognizerResult, DictAnalyzerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import EngineResult
from pydantic import BaseModel
from presidio_analyzer import PatternRecognizer, Pattern, RecognizerRegistry, AnalyzerEngine
from flask import Flask, request, jsonify



app = FastAPI()

global global_analyzer
global_analyzer = AnalyzerEngine()

def dataset_analysis(dataset, analyzer=global_analyzer, cutoff=0.6):
   
    # create analyzer engine
    if analyzer == None:
        analyzer = global_analyzer

    # create a dictionary to store the findings for each column
    all_columns_info = {}

    # analyze each value and record entity scores and counts
    for col in dataset.columns:
        # create dictionaries to store entity scores and counts for each column
        entity_scores = defaultdict(list)
        entity_counts = defaultdict(int)

        total_rows = len(dataset[col])

        for value in dataset[col]:
            # Call analyzer to get results
            try:
                results = analyzer.analyze(text=value, language='en')
                
                if not results:  # If no entities are found
                    entity_counts['NOT PII'] += 1

                # iterate over each result
                for result in results:
                    # add score and count to entity_scores and entity_counts dictionaries
                    entity_scores[result.entity_type].append(result.score)
                    entity_counts[result.entity_type] += 1
            except ValueError:
                pass

        # calculate the total entities found in the column
        total_entities = sum(entity_counts.values())

        # calculate average score, count, and percentage for each entity
        entity_scores_counts = {}
        for entity, scores in entity_scores.items():
            score_avg = sum(scores) / len(scores)
            
            if score_avg < cutoff:
                entity_counts['NOT PII'] += entity_counts.pop(entity)
            else:
                count = entity_counts[entity]
                percentage = (count / total_rows) * 100
                entity_scores_counts[entity] = {'score_average': score_avg, 'number_of_datapoints': count, 'percentage': percentage}

        # Add the 'NOT PII' class and its percentage
        not_pii_count = entity_counts['NOT PII']
        not_pii_percentage = (not_pii_count / total_rows) * 100
        entity_scores_counts['NOT PII'] = {'score_average': 0, 'number_of_datapoints': not_pii_count, 'percentage': not_pii_percentage}

        # store findings for the current column
        all_columns_info[col] = entity_scores_counts

    results_df = pd.DataFrame.from_dict({(i, j): all_columns_info[i][j]
                                        for i in all_columns_info.keys()
                                        for j in all_columns_info[i].keys()},
                                        orient='index')

    results_df.columns = ['score_average', 'n_datapoints', 'percentage']
    results_df = results_df.reset_index().rename(columns={'level_0': 'column', 'level_1': 'type'})

    # display the results
    print(results_df)
    return results_df

from fastapi import HTTPException

@app.post("/analyze-csv")
async def analyze_csv(file: UploadFile = File(...)):
    # Read the uploaded CSV file
    content = await file.read()
    content_str = content.decode()

    try:
        dataset = pd.read_csv(StringIO(content_str))
    except pd.errors.ParserError as e:
        raise HTTPException(status_code=400, detail=f"Error parsing CSV: {e}")

    # Perform the analysis
    results_df = dataset_analysis(dataset)

    # Convert the results DataFrame to a dictionary and return it
    grouped_results = {}
    for record in results_df.to_dict(orient="records"):
        column = record.pop("column")
        if column not in grouped_results:
            grouped_results[column] = {"types": []}
        grouped_results[column]["types"].append(record)

    return grouped_results

class DataInput(BaseModel):
    data: str
    col_num: int

# Your existing function to get a column from a DataFrame
def get_csv_column(df, col_num):
    if 0 <= col_num < len(df.columns):
        selected_column = df[[df.columns[col_num]]]
        print(f"Selected column '{df.columns[col_num]}':")
        print(selected_column)
        return selected_column
    else:
        print("Invalid column number.")
        return

def user_column_detection(dataset):
    for i, col in enumerate(dataset.columns):
        print(f"{i}: {col}")

    # Get the user input for the column number
    col_num = int(input("Enter the column number you want to select: "))
    column = dataset.iloc[:,[col_num]]
    dataset_analysis(column)


# POST route to accept DataFrame and column number
# POST route to accept a CSV file and user input for the column number
@app.post("/column_detection")
async def column_detection_api(file: UploadFile = File(...), col_num: int = 0):
    # Load the DataFrame from the uploaded file
    content = await file.read()
    content_str = content.decode()

    try:
        dataset = pd.read_csv(StringIO(content_str))
    except pd.errors.ParserError as e:
        raise HTTPException(status_code=400, detail=f"Error parsing CSV: {e}")

    # Call the user_column_detection function with the input DataFrame and column number
    results_df = user_column_detection(dataset, col_num)
    grouped_results = {}
    for record in results_df.to_dict(orient="records"):
        column = record.pop("column")
        if column not in grouped_results:
            grouped_results[column] = {"types": []}
        grouped_results[column]["types"].append(record)

    return grouped_results




