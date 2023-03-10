# AWS-Security-Hub-Findings

## Requirement

Python 3.11

Pipenv

## Install App Dependencies

Clone this repo and from your terminal/command prompt run the command

**pipenv install**

Also, add the google sheet ID to a .env file using the sample.env for reference.

Sample Sheet can be found here:

<https://docs.google.com/spreadsheets/d/1is8JgU_VpTuTWLXHKTBkD0P1EgM4r4uSDEZaxQ7S1bY>

## Setting up Google credentials

### **Authorize credentials for a desktop application**

To allow access to the google sheet you need to create an OAuth 2.0 Client ID. A client ID is used to identify a single app to Google's OAuth servers.

1.  In the Google Cloud console, go to **Menu \> APIs & Services \> Credentials.**  
    [Go to Credentials](https://console.cloud.google.com/apis/credentials)
2.  Click **Create Credentials** \> **OAuth client ID**.
3.  Click **Application type** \> **Desktop app**.
4.  In the **Name** field, type a name for the credential. This name is only shown in the Google Cloud console.
5.  Click **Create**. The OAuth client-created screen appears, showing your new Client ID and Client secret.
6.  Click **OK**. The newly created credential appears under **OAuth 2.0 Client IDs.**
7.  Save the downloaded JSON file as **creds.json**, and move the file to your working directory.

Using the service account email that is generated you will need to add it to the sheet with edit permission.

Reference: <https://developers.google.com/sheets/api/quickstart/python>

## Running the App

To run the app run the following command from your terminal/command prompt

**pipenv run python run.py**
