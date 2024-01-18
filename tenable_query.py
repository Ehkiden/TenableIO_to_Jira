import requests
import json
from datetime import datetime
import tenableIO_to_jira_json
import os

'''
This script should run every Tuesday and Friday morning before the next Tenable scan begins. The script will send a query request to Splunk to run a saved search that looks for new critical and high vulns with fixes. The critical and high severity is based on Tenable's VPR score. 
Results from Splunk are considered more accurate and easier to query.

Purpose: Gathers Tenable IO scans for new critical vulnerabilities per asset and creates Jira tasks for MDM. 
'''

def lambda_handler(event, lambda_context):
    today = datetime.weekday(datetime.now())
    earliest_time = '-3d@d'
    if today==1:    # Tuesday
        earliest_time = '-4d@d'
    elif today==4:  # Friday
        earliest_time = '-3d@d'

    splunk_tenant = os.environ['splunk_tenant']
    splunk_user = os.environ['splunk_user']
    splunk_ps = os.environ['splunk_ps']

    results_data = {
        "output_mode": "json"
    }
    # setup a search
    data = {
        'search': f' savedsearch "Tenable_to_Jira"',
        'earliest_time': earliest_time,
        'latest_time': '-1d@d',
        'output_mode': 'json'
    }

    # create the job
    saved_search = requests.post(f'https://{splunk_tenant}.splunkcloud.com:8089/services/search/jobs', data=data, verify=False,
                             auth=(splunk_user, splunk_ps))
    # get the job sid
    job = json.loads(saved_search.text)
    
    # keep checking until be get a response
    flag = False
    while flag != True:
        results = requests.get(f'https://{splunk_tenant}.splunkcloud.com:8089/services/search/jobs/{job["sid"]}/results',
                               data=results_data, verify=False,
                               auth=(splunk_user, splunk_ps))
        if results.status_code == 200:
            flag = True


    tenable_results = (json.loads(results.text))['results']

    if len(tenable_results)>0:
        # send data to be formatted and sent to jira
        tenableIO_to_jira_json.meaningful_jira(tenable_results)
        return {
            'statusCode': 200,
            'body': json.dumps('Script exited safely!')
        }
    return {
        'statusCode': 200,
        'body': json.dumps('No results were returned!')
    }
