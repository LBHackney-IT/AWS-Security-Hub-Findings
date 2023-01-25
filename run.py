import os
import logging
import boto3
import gspread
from oauth2client.service_account import ServiceAccountCredentials


logger = logging.getLogger()
logging.basicConfig()
level = logging.getLevelName(os.getenv('LOG_LEVEL', 'INFO'))
logger.setLevel(level)


def main():
    """This is the main function that gets the sheet id and updates the sheet with the findings
    """
    logger.info("Starting Security Hub Findings Search")
    # Set the google sheets document ID
    google_sheet_id = os.getenv('GOOGLE_SHEET_ID')     
    # Get the Google client 
    client = google_client()
    # Accessing the Main sheet
    sheet = client.open_by_key(google_sheet_id).worksheet("Data")
    # Clear the data in the sheet
    clear_sheet(sheet)
    # Get a list of the findings
    security_hub_list = get_list_securityhub()
    logger.info("Saving Security Hub Findings Search") 
    # Update the sheet with the findings
    sheet.update("A2",security_hub_list)
    logger.info("Security Hub Findings Search Complete")

def google_client():
    """Defines the scope and look for valid credentials

    Returns:
        class: With assigned credentials
    """
    # Setting up the scope to access and edit google sheets
    scope = ["https://spreadsheets.google.com/feeds", 'https://www.googleapis.com/auth/spreadsheets',
             "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive"]
    
    # Assign credentials 
    creds = ServiceAccountCredentials.from_json_keyfile_name("creds.json", scope)
    client = gspread.authorize(creds)
    return client

def clear_sheet(sheet):
    """This is to clear the data in the Google sheet and the add the header row
    Args:
        sheet (class): This is the worksheet with specified worksheet id
    """
    sheet.clear()
    header = ["Id","GeneratorId","AwsAccountId","Title","Description","Severity","Remediation_Text","Remediation_URL"]
    index = 1
    sheet.insert_row(header, index)

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

        finding_list = []
        finding_list.append(finding['Id'])
        finding_list.append(finding['GeneratorId'])
        finding_list.append(finding['AwsAccountId'])
        finding_list.append(finding['Title'])
        finding_list.append(finding['Description'])
        finding_list.append(finding['Severity']['Label'])
        finding_list.append(finding['Remediation']['Recommendation'].get('Text',""))
        finding_list.append(finding['Remediation']['Recommendation'].get('Url',""))

        securityhub_ids.append(finding_list)

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
    # session = boto3.Session(profile_name='audit')
    client = boto3.client(client_type, region_name='eu-west-2')
    paginator = client.get_paginator(operation)
    page_iterator = paginator.paginate(**operation_parameters)
    results = []
    for page in page_iterator:
        results.extend(page[response_key])
    return results

if __name__ == "__main__":
    main()