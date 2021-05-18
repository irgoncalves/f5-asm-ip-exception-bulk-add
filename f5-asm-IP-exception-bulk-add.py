# This generates a payload.json file dynamically on a proper format to send a task to BIG-IP ASM / Adv. WAF to add IP addresses exceptions in bulk
# Written by Ismael Goncalves
# Tested on BIG-IP 15.1.x
#
#!/usr/bin/python

import sys

payload = open("payload.json","w+")

# TODO: retrieve policy ID dynamically or receive input from argv
#curl -sk -u admin:admin -H "Content-Type: application/json" "https://10.128.1.210/mgmt/tm/asm/policies/?\$select=name,id" | jq '.items[] | select(.name | contains ("parent"))'
#{
#  "kind": "tm:asm:policies:policystate",
#  "selfLink": "https://localhost/mgmt/tm/asm/policies/dQfGttMq8-OxlwlnVD0-ww?ver=15.1.2",
#  "name": "parent-policy",
#  "id": "dQfGttMq8-OxlwlnVD0-ww"
#}

policy_id = "dQfGttMq8-OxlwlnVD0-ww" 

# TODO: obtain IP file from argv
# TODO: implement support for various parameters such as blockRequest, ignoreAnomalies, netmask etc
# File IP.txt should contain IP list by line 
#
# 10.128.1.210
# 10.128.2.220
# 10.130.1.110

with open("IP.txt","r") as file:
  initial_payload =  """ { 
             "commands": [ 
             """
             
  payload.write(initial_payload)
  
  for line in file:

    tmpl_str = """ {
            "body": {
                       "ipAddress": "%s",
                       "ipMask": "255.255.255.255",
                       "ignoreIpReputation": true,
                       "blockRequests": "never",
                       "ignoreAnomalies": true,
                       "neverLogRequests": true,
					   "description": "Qualys Scanner",
                       "neverLearnRequests": true,
					   "trustedByPolicyBuilder": false
                    },
            "method": "POST",
            "uri": "https://localhost/mgmt/tm/asm/policies/%s/whitelist-ips/"
        }, """ % (line.rstrip("\r\n"),policy_id)

    payload.write(tmpl_str)
  
  final_payload =  """ 
                     ]
                    } """
  
  payload.seek(-2,1)                  
  payload.write(final_payload)
  payload.close()

# TODO: send API request with @payload.json 
# curl -sk -u admin:admin -H "Content-Type: application/json" "https://10.128.1.210/mgmt/tm/asm/tasks/bulk" -X POST -d @payload.txt
# ...
#    }
#  ],
#  "lastUpdateMicros": 1621374423000000,
#  "kind": "tm:asm:tasks:bulk:bulk-taskstate",
#  "selfLink": "https://localhost/mgmt/tm/asm/tasks/bulk/tvYx4ZswoplTW2zdBDOiNQ?ver=15.1.2",
#  "createResultReference": false,
#  "transaction": true,
#  "startTime": "2021-05-18T21:47:03Z",
#  "id": "tvYx4ZswoplTW2zdBDOiNQ",
#  "timeoutSeconds": 0
#}
# TODO: retrieve the status of the transaction
# curl -sk -u admin:admin -H "Content-Type: application/json" https://10.128.1.210/mgmt/tm/asm/tasks/bulk/tvYx4ZswoplTW2zdBDOiNQ
