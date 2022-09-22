# Overview 
The script's purpose is to provide a list of signatures with a description of the signature that DefensePro's profile is using (SignatureList.csv and SignatureList.json).
The script interacts with Radware APSolute Vision and DefensePro (via APSolute Vision) and collects all the necessary data through REST API calls.


## IMPORTANT
● Read the entire file before attempting to configure or execute it.


# Script Output
The script output generates one report in both CSV and JSON format in the same script directory (SignatureList.csv and SignatureList.json).
Note: CVS default 
To read the signature description columns on the CSV file, please select all the data and perform AutoFit columns and rows(https://support.microsoft.com/en-us/office/change-the-column-width-and-row-height-72f5e3cc-994d-43e8-ae58-9774a0905f46).


# Setup

## Requirements
The solution requires Python 3.6 or higher.

### Packages required but should be part of the standard 3.6 library- no need to install
requests
json
csv
os

### Packages required but may requires installation
urllib3

## Instructions and recommendations

1. Please ensure that Vision has scheduled a signature task to update the signature database (SUS) and a signature description.
2. Place the script in the appropriate location/folder on the server.
3. Install dependencies and necessary libraries & packages.
4. Rename the file 'config example.py' to 'config.py' and set the appropriate values.
5. Set up the script to run periodically (optional) through cron (linux) or Windows Scheduler on Windows:

    Linux cron example:
    0 4 * * * /path/to/app/python3 main.py #example setting the script to run every day at 4 am.

6. Navigate to the folder containing the script and run it.
python3 main.py


## Version log
1.0 Original Scrit (09/21/2022)
1.1 Print Output on Console (09/22/2022)