## AWS Security Hub Automation Rules multi-region deployment scripts

These scripts automate the process of deploying Security Hub automation rules to multiple regions within an account that is in your control.  

The **automation-rule-create.py** script is intended to be run from the Delegated Administrator account for Security Hub.  This script will take in a list of regions as well as the location for the file that contains the rule definition.  The rule definition will then be deployed to each region. 

The **list-automation-rules.py** script will return a list of automation rules that are deployed across multiple regions.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.   



## Prerequisites
The **automation-rule-create.py** script depends on a file containing the json definition of the rule that needs to be deployed.  The schema for an automation rule definition is outlined [HERE.](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_CreateAutomationRule.html)  This repository contains an example of a single rule definition in the **automation-rule-definition.json** file.  If you want to deploy multiple rules the **automation-rule-definition-mult-rules.json** file contains an example of how to define multiple rules.  


## Steps to deploy an automation rule
### 1. Setup execution environment
* Clone the repository
  * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
  * cd aws-securityhub-multiaccount-scripts/automation-rules
* Stage the automation rule definition json file in a local directory.

### 2. Execute Script

```
usage: automation-rules-create.py [-h] --input_file PATH_TO_RULE_DEFINITION_FILE
                                       --enabled_regions ENABLED_REGIONS
                                      
Deploy automation rules across regions
                        
required arguments:
  -h, --help            show this help message and exit
  
  --input_file INPUT_FILE
                        Path to the json file containing the rule definition.

  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to deploy the rule to.
                        If not specified, rule will be deployed to all available regions 
                        where Security Hub is enabled.  
```

```
Example usage:
$ python3 automation-rules-create.py --input_file /home/user/automation-rule-definition.json --enabled_regions eu-north-1,us-west-2,us-east-1
```

## Listing automation rules across regions
### 1. Setup execution environment
* Clone the repository
  * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
  * cd aws-securityhub-multiaccount-scripts/automation-rules

### 2. Execute Script

```
usage: list-automation-rules.py [-h] --deployed_regions DEPLOYED_REGIONS
                                  
List automation rules across regions
                        
required arguments:
  -h, --help            show this help message and exit
  
  --deployed_regions DEPLOYED_REGIONS
                        comma separated list of regions to list rules from.
                        If not specified, list operation will run for all available regions 
                        where Security Hub is enabled.  
```

```
Example usage:
python3 list-automation-rules.py --deployed_regions us-east-1,us-east-2,us-west-2
```