#!/usr/bin/env python
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
import re
import argparse
import time
import utils

from collections import OrderedDict
from botocore.exceptions import ClientError


def get_master_members(sh_client, aws_region):
    """
    Returns a list of current members of the SecurityHub master account
    :param aws_region: AWS Region of the SecurityHub master account
    :param detector_id: DetectorId of the SecurityHub master account in the AWS Region
    :return: dict of AwsAccountId:RelationshipStatus
    """

    member_dict = dict()

    results = sh_client.list_members(
        OnlyAssociated=False
    )
    
    for member in results['Members']:
        member_dict.update({member['AccountId']: member['MemberStatus']})
        
    while results.get("NextToken"):
        results = sh_client.list_members(
            OnlyAssociated=False,
            NextToken=results['NextToken']
        )
        
        for member in results['Members']:
            member_dict.update({member['AccountId']: member['MemberStatus']})
            
    return member_dict

def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role in each account and returns a SecurityHub client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: SecurityHub client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')
    
    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    
    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='EnableSecurityHub'
    )
    
    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for {}.".format(
        aws_account_number
    ))

    return session

if __name__ == '__main__':
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Disable and unlink AWS Accounts from central SecurityHub Account')
    parser.add_argument('--master_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file containing the list of account IDs and Email addresses')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--delete_master', action='store_true', default=False, help="Disable SecurityHub in Master")
    parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to remove SecurityHub. If not specified, all available regions disabled")
    parser.add_argument('--disable_standards_only', type=str, required=False,help="comma separated list of standards ARNs to disable (ie. arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0 )")
    args = parser.parse_args()
    
    # Validate master accountId
    if not re.match(r'[0-9]{12}',args.master_account):
        raise ValueError("Master AccountId is not valid")
    
    
    # Generate dict with account & email information
    aws_account_dict = OrderedDict()
    
    for acct in args.input_file.readlines():
        split_line = acct.rstrip().split(",")
        if len(split_line) < 2:
            print("Unable to process line: {}".format(acct))
            continue
            
        if not re.match(r'[0-9]{12}',str(split_line[0])):
            print("Invalid account number {}, skipping".format(split_line[0]))
            continue
            
        aws_account_dict[split_line[0]] = split_line[1]
    
    # Getting SecurityHub regions
    session = boto3.session.Session()
    securityhub_regions = []
    if args.disable_standards_only: 
        standards_arns = [str(item) for item in args.disable_standards_only.split(',')]
        if args.enabled_regions:
            securityhub_regions = [str(item) for item in args.enabled_regions.split(',')]
            print("Disabling standards: {} in these regions: {}".format(args.disable_standards_only, securityhub_regions))
        else:
            securityhub_regions = session.get_available_regions('securityhub')
            print("Disabling standards: {} in all available SecurityHub regions {}".format(args.disable_standards_only,securityhub_regions))
    
    else:
        if args.enabled_regions:
            securityhub_regions = [str(item) for item in args.enabled_regions.split(',')]
            print("Disabling members in these regions: {}".format(securityhub_regions))
        else:
            securityhub_regions = session.get_available_regions('securityhub')
            print("Disabling members in all available SecurityHub regions {}".format(securityhub_regions))
    
    master_session = assume_role(args.master_account, args.assume_role)
    #master_session = boto3.Session()
    master_clients = {}
    members = {}
    for aws_region in securityhub_regions:
        master_clients[aws_region] = master_session.client('securityhub', region_name=aws_region)
        members[aws_region] = get_master_members(master_clients[aws_region], aws_region)

    # Processing accounts to be linked
    failed_accounts = []
    for account in aws_account_dict.keys():
        try:
            session = assume_role(account, args.assume_role)
            
            for aws_region in securityhub_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))
                
                sh_client = session.client('securityhub', region_name=aws_region)
                if args.disable_standards_only:
                    regional_standards_arns = [utils.get_standard_arn_for_region_and_resource(aws_region, standard) for standard in standards_arns]
                    for standard in regional_standards_arns:
                        try:
                            subscription_arn = 'arn:aws:securityhub:{}:{}:subscription/{}'.format(aws_region, account,standard.split(':')[-1].split('/',1)[1])
                            sh_client.batch_disable_standards(StandardsSubscriptionArns=[subscription_arn])
                            print("Finished disabling standard {} on account {} for region {}".format(standard,account, aws_region))
                        except ClientError as e:
                            print("Error disabling standards for account {}".format(account))
                            failed_accounts.append({ account : repr(e)})
                else:
                    if account in members[aws_region]:
                    
                        if sh_client.get_master_account().get('Master'):
                            try:
                                response = sh_client.disassociate_from_master_account()
                
                            except ClientError as e:
                                print("Error Processing Account {}".format(account))
                                failed_accounts.append({
                                    account: repr(e)
                                })
                        
                        master_clients[aws_region].disassociate_members(
                            AccountIds=[account]
                        )
                        
                        time.sleep(2)
                        
                        master_clients[aws_region].delete_members(
                            AccountIds=[account]
                        )
                    
                        print('Removed Account {monitored} from member list in SecurityHub master account {master} for region {region}'.format(
                            monitored=account,
                            master=args.master_account,
                            region=aws_region
                        ))
                                    
                        start_time = int(time.time())
                        while account in members[aws_region]:
                            if (int(time.time()) - start_time) > 300:
                                print("Membership did not show up for account {}, skipping".format(account))
                                failed_accounts.append({
                                    account: "Membership did not show up for account {} in {}".format(
                                        account,
                                        aws_region
                                    )
                                })
                                break
                            
                            time.sleep(5)
                            members[aws_region] = get_master_members(master_clients[aws_region], aws_region)

                    else:
                        print('Account {monitored} is not a member of {master} in region {region}'.format(
                            monitored=account,
                            master=args.master_account,
                            region=aws_region
                        ))
                    
                    sh_client.disable_security_hub()

            # Refresh the member dictionary
            members[aws_region] = get_master_members(master_clients[aws_region], aws_region)
                    
            print('Finished {account} in {region}'.format(account=account, region=aws_region))
                    
        except ClientError as e:
            print("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })

    if args.delete_master and len(failed_accounts) == 0 and not args.disable_standards_only:
        for aws_region in securityhub_regions:
            master_clients[aws_region].disable_security_hub()
    if args.delete_master and len(failed_accounts) == 0 and  args.disable_standards_only:
        for aws_region in securityhub_regions:
            master_clients[aws_region].batch_disable_standards(StandardsSubscriptionArns = [ args.disable_standards_only])
    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            print("{}: \n\t{}".format(
                account.keys()[0],
                account[account.keys()[0]]
            ))
            print("---------------------------------------------------------------")
