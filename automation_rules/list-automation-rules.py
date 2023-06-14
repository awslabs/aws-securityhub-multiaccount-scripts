#!/usr/bin/env python3
"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import boto3
import argparse
import json

from botocore.exceptions import ClientError

parser = argparse.ArgumentParser(description='List deployed automation rules in one or many regions.')
parser.add_argument('--deployed_regions', type=str, required=False, help="Comma separated list of regions to list rules from. If not specified, rules from all regions will be retrieved.")
args = parser.parse_args()

# Getting SecurityHub regions
session = boto3.session.Session()

securityhub_regions = []
if args.deployed_regions:
    securityhub_regions = [str(item) for item in args.deployed_regions.split(',')]
    print("Listing rules in these regions: {}".format(securityhub_regions))
else:
    securityhub_regions = session.get_available_regions('securityhub')
    print("Listing rules in all available SecurityHub regions {}".format(securityhub_regions))

for aws_region in securityhub_regions:

    print('*******************************************')
    print('Retrieving rules from region: ',aws_region)
    sh_client = session.client('securityhub', region_name=aws_region)

    try:
        response=sh_client.list_automation_rules()

        if len(response['AutomationRulesMetadata']) > 0:
            for msg in response['AutomationRulesMetadata']:
                rule_arn = msg['RuleArn']
                rule_name = msg['RuleName']
                rule_status = msg['RuleStatus']
                rule_order = msg['RuleOrder']
                print('------------------------------------')
                print("Rule ARN: ",rule_arn)
                print("Rule Name: ",rule_name)
                print("Rule Status: ",rule_status)
                print("Rule Order: ",rule_order)
        else:
            print("No rules in this region")

    except ClientError as e:
            print("Error Processing Region {}".format(aws_region))
            print(e)
            


    
