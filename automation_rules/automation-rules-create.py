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

parser = argparse.ArgumentParser(
    description="Deploy Security Hub automation rules to multiple regions."
)
parser.add_argument(
    "--enabled_regions",
    type=str,
    required=False,
    help="Comma separated list of regions to deploy the rule to. If not specified, rule will be deployed to all available regions.",
)
parser.add_argument(
    "--input_file",
    type=argparse.FileType("r"),
    help="Path to json file containing the rule definition.",
)
args = parser.parse_args()

rule_definition = json.load(args.input_file)

# Getting SecurityHub regions
session = boto3.session.Session()

securityhub_regions = []
eligible_regions = []
if args.enabled_regions:
    eligible_regions = [str(item) for item in args.enabled_regions.split(",")]
    print("Deploying rule in these regions: {}".format(eligible_regions))
else:
    print("No regions provided.  Getting list of eligible regions")
    securityhub_regions = session.get_available_regions("securityhub")
    for aws_region in securityhub_regions:
        acct_client = session.client("account")
        acct_response = acct_client.get_region_opt_status(RegionName=aws_region)
        region_status=(acct_response['RegionOptStatus'])
        if region_status in ['ENABLED','ENABLED_BY_DEFAULT']:
            eligible_regions.append(aws_region)

    print(
        "Deploying rule in all available SecurityHub regions {}".format(
            eligible_regions
        )
    )


failed_regions = []
for aws_region in eligible_regions:
    print("Deploying rule to region: ", aws_region)
    sh_client = session.client("securityhub", region_name=aws_region)
    cnt = 1
    try:
        if isinstance(rule_definition, dict):
            rule_definition = [rule_definition]
        for rule in rule_definition:
            if not "RuleOrder" in rule:
                rule["RuleOrder"] = cnt
                cnt += 1
            if not "Description" in rule:
                rule[
                    "Description"
                ] = f"Automatically created rule for {rule.get('RuleName','')}"

            sh_client.create_automation_rule(**rule)
            print(f"Rule {rule.get('RuleName','')} deployed successfully.")

    except ClientError as e:
        print("Error Processing Region {}".format(aws_region))
        failed_regions.append({aws_region: repr(e)})

if len(failed_regions) > 0:
    print("---------------------------------------------------------------")
    print("Failed Regions")
    print("---------------------------------------------------------------")
    print(failed_regions)
    for region in failed_regions:
        for region_name, message in region.items():
            print("{}: \n\t{}".format(region_name, message))
    print("---------------------------------------------------------------")
