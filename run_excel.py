import os
import logging
import boto3
import json
import pandas as pd

logger = logging.getLogger()
logging.basicConfig()
level = logging.getLevelName(os.getenv('LOG_LEVEL', 'INFO'))
logger.setLevel(level)

def main():
    logger.info("Starting Security Hub Findings Search")
    Security_Hub_list = get_list_securityhub()
    
    logger.info("Saving Security Hub Findings") 
    df_json = pd.read_json(json.dumps(Security_Hub_list))
    df_json.to_excel("Security Hub Findings.xlsx",index=False)
    
    logger.info("Security Hub Findings Search Complete")

def get_list_securityhub() -> list[str]:
    """Gets all security hub items.
    Returns:
        list[str]: of filtered security hub finding according to the filter specified.
    """
    operation_filters = {'Filters': {
            'SeverityLabel': 
            [
                {
                    'Value': 'CRITICAL',
                    'Comparison': 'EQUALS'
                }
            ],
            'WorkflowStatus': 
            [
                {
                    'Value': 'RESOLVED',
                    'Comparison': 'NOT_EQUALS'
                }
            ]
            }
        }
    
    response = paginate_results(client_type='securityhub', operation='get_findings', operation_parameters=operation_filters, response_key='Findings')
    securityhub_ids = []
    for finding in response:
       
        securityhub_ids.append({
            'Id': finding['Id'],
            'GeneratorId': finding['GeneratorId'],
            'AwsAccountId': finding['AwsAccountId'],
            'Title': finding['Title'],
            'Description': finding['Description'],
            'Severity': finding['Severity']['Label'],
            'Remediation_Text': finding['Remediation']['Recommendation'].get('Text',""),
            'Remediation_URL': finding['Remediation']['Recommendation'].get('Url',"")
            })

    return securityhub_ids

def paginate_results(client_type: str, operation: str, response_key: str, operation_parameters: dict = {}) -> list[dict]:
    """Helper function to paginate AWS API requests
    Args:
        client_type (str): The type of boto client to create e.g. ec2, rds, ddb etc.
        operation (str): The type of API operation to perform.
        response_key (str): The key to extend the pagionation results into.
        operation_parameters (dict, optional): Dictionary of operational parameters relevant to the API operation being performed. Defaults to {}.
    Returns:
        list[dict]: List of dictionary reponses from AWS
    """
    client = boto3.client(client_type, region_name='eu-west-2')
    paginator = client.get_paginator(operation)
    page_iterator = paginator.paginate(**operation_parameters)
    results = []
    for page in page_iterator:
        results.extend(page[response_key])
    return results

if __name__ == "__main__":
    main()