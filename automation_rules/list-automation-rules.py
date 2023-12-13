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
import argparse
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Custom Config for adaptive retry strategy
custom_config = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# Argument Parsing
parser = argparse.ArgumentParser(
    description="List and save deployed automation rules in one or many regions."
)
parser.add_argument(
    "--deployed_regions",
    type=str,
    required=False,
    help="Comma-separated list of regions to list rules from. If not specified, rules from all regions will be retrieved.",
)
parser.add_argument(
    "--save-rules-json",
    action="store_true",
    help="Save the rules as JSON files in the current directory with region name appended.",
)
args = parser.parse_args()


# Function to save rule to JSON
def save_rule_to_json(rule_name, rule_data, region):
    """
    Saves the given rule data to a JSON file with the given name and region.

    Args:
        rule_name (str): The name of the rule.
        rule_data (dict): The data for the rule to be saved.
        region (str): The region where the rule is saved.

    Returns:
        None
    """
    filename = f"{rule_name}_{region}.json"
    with open(filename, "w", encoding="UTF-8") as file:
        json.dump(rule_data, file, indent=4, sort_keys=True, default=str)
        print(f"Saved rule '{rule_name}' to JSON file in {region}.")


# Boto3 Session
session = boto3.session.Session()

# Determine SecurityHub regions
securityhub_regions = (
    args.deployed_regions.split(",")
    if args.deployed_regions
    else session.get_available_regions("securityhub")
)
print("Processing these regions: {}".format(securityhub_regions))

# Process each region
for aws_region in securityhub_regions:
    print("*******************************************")
    print("Retrieving rules from region: ", aws_region)
    sh_client = session.client(
        "securityhub", region_name=aws_region, config=custom_config
    )

    try:
        rule_arns = []
        next_token = ""
        while True:
            if next_token:
                response = sh_client.list_automation_rules(
                    MaxResults=100, NextToken=next_token
                )
            else:
                response = sh_client.list_automation_rules(MaxResults=100)

            rules = response.get("AutomationRulesMetadata", [])
            rule_arns.extend([rule["RuleArn"] for rule in rules])

            next_token = response.get("NextToken")
            if not next_token:
                break
        if rules:
            for msg in rules:
                rule_arn = msg["RuleArn"]
                rule_name = msg["RuleName"]
                rule_status = msg["RuleStatus"]
                rule_order = msg["RuleOrder"]
                print("------------------------------------")
                print("Rule ARN: ", rule_arn)
                print("Rule Name: ", rule_name)
                print("Rule Status: ", rule_status)
                print("Rule Order: ", rule_order)
        else:
            print("No rules in this region")
        # Getting full rule definitions
        if rule_arns:
            rule_defs_response = sh_client.batch_get_automation_rules(
                AutomationRulesArns=rule_arns
            )
            rule_defs = rule_defs_response.get("Rules", [])  # Corrected key here
            for rule_def in rule_defs:
                rule_name = rule_def["RuleName"]
                print(f"Processing rule: {rule_name}")
                if args.save_rules_json:
                    save_rule_to_json(rule_name, rule_def, aws_region)

    except ClientError as e:
        print(f"Error processing region {aws_region}: {e}")
