import requests
import json
import csv
import os

'''
Purpose: A helper file to build the json template for jira and fill out the important bits. Also creates a cvs file containing the affected hostnames and attaches that to the created file.

Creating a json array for jira:
https://developer.atlassian.com/cloud/jira/platform/apis/document/playground/
'''

# ref https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-attachments/#api-rest-api-3-issue-issueidorkey-attachments-post
def jira_csv_upload(jira_id):
    jira_domain = os.environ['jira_domain']
    url = f"https://{jira_domain}.atlassian.net/rest/api/3/issue/{jira_id}/attachments"
    
    jira_email = os.environ['jira_email']
    auth = requests.auth.HTTPBasicAuth(
        jira_email, os.environ['jira_auth'])

    headers = {
        "Accept": "application/json",
        "X-Atlassian-Token": "no-check"
    }
    try:
        resp = json.loads(requests.post(url, auth=auth, files={
            "file": (f"/tmp/{jira_id}.csv", open(f"/tmp/{jira_id}.csv", "rb"), "application-type")
        }, headers=headers).content)
        print(f"Successfully uploaded csv to jira ticket {jira_id}.")

    except Exception as e:
        print(f"An error occurred when trying to add an attachment to jira ticket {jira_id}.")
        print(e)


# creates csv file then deletes after being sent to jira
def host_csv(jira_id, host_array):
    temp_host_array = []
    # check if host array is a list
    if bool(host_array) and not(isinstance(host_array, list)):
      temp_host_array.append([host_array])
    else:
        for i in host_array:
            temp_host_array.append([i])
        # temp_host_array = host_array
    # insert the header at the beginning of the array
    temp_host_array.insert(0, ['hostname'])
    
    with open(f"/tmp/{jira_id}.csv", "w+") as my_csv:
        csvWriter = csv.writer(my_csv)
        csvWriter.writerows(temp_host_array)

    jira_csv_upload(jira_id)
    # cleanup
    os.remove(f"/tmp/{jira_id}.csv")

# ref: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-bulk-post
# def jira_bulk_issues(jira_payload):
def jira_issues(jira_payload):
    jira_domain = os.environ['jira_domain']
    url = f"https://{jira_domain}.atlassian.net/rest/api/3/issue"
    
    jira_email = os.environ['jira_email']
    auth = requests.auth.HTTPBasicAuth(jira_email, os.environ['jira_auth'])

    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
    }

    try:
        resp = json.loads(requests.post(url, auth=auth, data=json.dumps(jira_payload), headers=headers).content)
        print(f"Successfully created jira ticket {resp['id']}.")
    except Exception as e:
        print("An error occurred when trying to create a jira ticket.")
        print(e)
        print(json.dumps(jira_payload))

    return resp

# creates the individual vuln jira formatted json entries
def jira_json_builder(plugin_dets):

    temp_cve_array = []
    if bool(plugin_dets['cve_array']) and not(isinstance(plugin_dets['cve_array'], list)):
        temp_cve_array.append(plugin_dets['cve_array'])
    else:
        temp_cve_array = plugin_dets['cve_array']

    cve_array = []
    for i in temp_cve_array:
        cve_array.append({
          "type": "listItem",
          "content": [
            {
              "type": "paragraph",
              "content": [
                {
                  "type": "text",
                  "text": i
                }
              ]
            }
          ]
        })

    jira_json_description = {
      "version": 1,
      "type": "doc",
      "content": [
        {
          "type": "heading",
          "attrs": {
            "level": 2
          },
          "content": [
            {
              "type": "text",
              "text": f"New {plugin_dets['vuln_severity']} vulnerability has been detected:"
            }
          ]
        },
        {
          "type": "paragraph",
          "content": [
            {
              "type": "text",
              "text": "Please refer to the attached csv for the list of affected hosts and the following vulnerability details for specifics including solution:"
            }
          ]
        },
        {
          "type": "heading",
          "attrs": {
            "level": 2
          },
          "content": [
            {
              "type": "text",
              "text": "Vulnerability:"
            }
          ]
        },
        {
          "type": "heading",
          "attrs": {
            "level": 3
          },
          "content": [
            {
              "type": "text",
              "text": plugin_dets['plugin_name']
            }
          ]
        },
        {
          "type": "paragraph",
          "content": [
            {
              "type": "text",
              "text": "Description:",
              "marks": [
                {
                  "type": "strong"
                }
              ]
            },
            {
              "type": "text",
              "text": plugin_dets['description']
            }
          ]
        },
        {
          "type": "table",
          "attrs": {
            "isNumberColumnEnabled": False,
            "layout": "default",
            "localId": "9ba5f690-9683-4830-87bd-41b6e72d19f5"
          },
          "content": [
            {
              "type": "tableRow",
              "content": [
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": "Vulnerability Family"
                        }
                      ]
                    }
                  ]
                },
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": plugin_dets['plugin_family']
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "type": "tableRow",
              "content": [
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": "Synopsis"
                        }
                      ]
                    }
                  ]
                },
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": plugin_dets['synopsis']
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "type": "tableRow",
              "content": [
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": "Exploit Ease"
                        }
                      ]
                    }
                  ]
                },
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": plugin_dets['exploitability_ease']
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "type": "tableRow",
              "content": [
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": "Solution"
                        }
                      ]
                    }
                  ]
                },
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": plugin_dets['solution']
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "type": "tableRow",
              "content": [
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": "Patch Publication Date"
                        }
                      ]
                    }
                  ]
                },
                {
                  "type": "tableCell",
                  "attrs": {},
                  "content": [
                    {
                      "type": "paragraph",
                      "content": [
                        {
                          "type": "text",
                          "text": plugin_dets['patch_publication_date']
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        },
        {
          "type": "heading",
          "attrs": {
            "level": 3
          },
          "content": [
            {
              "type": "text",
              "text": "CVE List"
            }
          ]
        },
        {
          "type": "bulletList",
          "content": cve_array
        }
      ]
    }

    # make sure 'see_also' field is present
    if 'see_also' in plugin_dets:

        temp_see_also_array = []
        if bool(plugin_dets['see_also']) and not(isinstance(plugin_dets['see_also'], list)):
            temp_see_also_array.append(plugin_dets['see_also'])
        else:
            temp_see_also_array = plugin_dets['see_also']

        see_also_array = []
        for j in temp_see_also_array:
            see_also_array.append({
                "type": "listItem",
                "content": [
                {
                    "type": "paragraph",
                    "content": [
                    {
                        "type": "text",
                        "text": j,
                        "marks": [
                        {
                            "type": "link",
                            "attrs": {
                            "href": j
                            }
                        }
                        ]
                    }
                    ]
                }
                ]
            })

        see_also_header = {
        "type": "heading",
        "attrs": {
            "level": 3
        },
        "content": [
            {
            "type": "text",
            "text": "See Also"
            }
        ]
        }

        see_also_body = ({
            "type": "bulletList",
            "content": see_also_array
        })

        jira_json_description['content'].append(see_also_header)
        jira_json_description['content'].append(see_also_body)

    # MDM prod id: 10021
    # MDM test id: 10022
    # TODO: change to MDM project id and check fields for diffs
    jira_payload = {
        "fields": {
            "project": {
                "id": "10021"
            },
            "summary": f"{plugin_dets['vuln_severity']} Vulnerability Found: {plugin_dets['plugin_name']}",
            "issuetype": {
                "id": "10002"
            },
            "priority": {
                "id": "5"
            },
            "description": jira_json_description,
            "customfield_10030": {
            "value": "No"
            },
            "customfield_10031": {
            "value": "No"
            },
            "customfield_10032": {
            "value": "No"
            },
            "customfield_10043": {
            "value": "Patch"
            }
        }
    }
    return jira_payload

# i ran out of names
def meaningful_jira(tenable_results):
    for i in tenable_results:
        try:
            jira_ticket = jira_issues(jira_json_builder(i))
            host_csv(jira_ticket['id'], i['hosts'])
        except Exception as e:
            print("An error occurred when trying to create jira issues.")
            print(e)
