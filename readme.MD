# Overview 
The purpose of the script is to provide a list of signatures with a description of the signature for a specific signature profile present on the DefensePro.
The script interacts with Radware APSolute Vision and DefensePro (via APSolute Vision) and collects all the necessary data through REST API calls.
**This script will also check and delete old reports as per the configured Retention Period**

## IMPORTANT
● Read the entire file before attempting to configure or execute it.


# Script Output
The script generates reports in both CSV and JSON format, and these are stored in the same directory from where the script is executed.
Format of FileName: "DpMgmtIP_ProfileName_YYYY-MM-DD_HH-MM-SS.csv" and "DpMgmtIP_ProfileName_YYYY-MM-DD_HH-MM-SS.json"

Note: To view all the data within the CSV file, please perform an AutoFit for the columns and rows.
Instructions > (https://support.microsoft.com/en-us/office/change-the-column-width-and-row-height-72f5e3cc-994d-43e8-ae58-9774a0905f46).

**Script to Delete old reports as per configured Retention Period**

# Setup

## Requirements
The solution requires Python 3.6 or higher.

### Packages required but should be part of the standard 3.6 library, if absent please Install
requests
json
csv
os
datetime
glob

### Necessary Package that may require Installation
urllib3

## Execution Instructions and recommendations

1. Please ensure that Vision has scheduled a signature task to update the signature database (SUS) and a signature description.
2. Place the script in the appropriate location/folder on the server.
3. Install dependencies and necessary libraries & packages.
4. Rename the file 'config example.py' to 'config.py' and set the appropriate values.
5. Set up the script to run periodically (optional) through cron (linux) or Windows Scheduler on Windows:
    Linux cron example:
    0 4 * * * /path/to/app/python3 main.py #example setting the script to run every day at 4 AM.

6. Navigate to the folder containing the script and run it.
python3 main.py


## Version log
1.0 Original Script (09/21/2022)
1.1 Print Output on Console (09/22/2022)