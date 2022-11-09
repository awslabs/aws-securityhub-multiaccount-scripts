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
import sys
import time
import argparse
import re
import string
import utils
import time

from botocore.exceptions import ClientError

CIS14_ARN_BASE = 'standards/cis-aws-foundations-benchmark/v/1.4.0'
CIS_14_CONTROL_BASE='control/cis-aws-foundations-benchmark/v/1.4.0'
CIS12_standard = 'subscription/cis-aws-foundations-benchmark/v/1.2.0'

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
    parser = argparse.ArgumentParser(description='Enable CIS 1.4 in Security Hub accounts')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account.")
    parser.add_argument('--enabled_regions', type=str, required=True, help="Comma separated list of regions to enable CIS 1.4. If not specified, all available regions enabled.")
    parser.add_argument('--map_cis12_disabled_controls', type=str, required=True, help="Yes or No value indidating if any CIS 1.4 controls should be disabled if they map to a CIS 1.2 control that is currently disabled in the account and region.")
    parser.add_argument('--disable_cis12', type=str, required=True, help="Yes or No value indicating if the CIS 1.2 standard should be disabled after enabling CIS 1.4.")
    parser.add_argument('--input_file', type=argparse.FileType('r'), help='Path to txt file containing the list of account IDs.')
    args = parser.parse_args()

    # Generate account list
    aws_account_list = []

    for acct in args.input_file.readlines():
        if not re.match(r'[0-9]{12}', str(acct)):
            print("Invalid account number {}, skipping".format(acct))
            continue

        aws_account_list.append(acct.rstrip())
    
    # Getting SecurityHub regions
    session = boto3.session.Session()

    securityhub_regions = []
    if args.enabled_regions:
        securityhub_regions = [str(item) for item in args.enabled_regions.split(',')]
        print("Enabling members in these regions: {}".format(securityhub_regions))
    else:
        securityhub_regions = session.get_available_regions('securityhub')
        print("Enabling CIS 1.4 in all available SecurityHub regions {}".format(securityhub_regions))


    # Processing accounts have CIS 1.4 enabled
    failed_accounts = []
    for account in aws_account_list:
        try:

            print('***********Account Loop***************')
            session = assume_role(account, args.assume_role)
            
            for aws_region in securityhub_regions:
                print('-----------Region Loop--------------')
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))

                sh_client = session.client('securityhub', region_name=aws_region)
                
                print('Enabling CIS 1.4')
                CIS14_ARN = 'arn:aws:securityhub:{}::{}'.format(aws_region, CIS14_ARN_BASE)
                sh_client.batch_enable_standards(StandardsSubscriptionRequests=[{'StandardsArn': CIS14_ARN}])

                print('Verifying the standard is enabled')
                # Verify standards get enabled
                standards_status = {}
                start_time = int(time.time())
                standard_enabled = False
                while standard_enabled == False:
                    
                    if (int(time.time()) - start_time) > 100:
                        print("Timeout waiting for READY state enabling CIS 1.4 in region {region} for account {account}, last state: {status}"
                              .format(region=aws_region, account=account, status=standards_status))
                        break
                    
                    enabled_standards = sh_client.get_enabled_standards()
                    
                    for enabled_standard in enabled_standards['StandardsSubscriptions']:
                        enabled_standard_arn = enabled_standard['StandardsArn']
                        enabled_standard_status = enabled_standard['StandardsStatus']
                        standards_status[enabled_standard_arn] = enabled_standard_status
                        
                        if enabled_standard_arn == CIS14_ARN and enabled_standard_status == 'READY':
                            print("Finished enabling standard CIS 1.4 on account {} for region {}".format(account, aws_region))
                            standard_enabled = True

                print('-----------Map disabled controls loop-----------')
                if args.map_cis12_disabled_controls == 'Yes':
                    print ('Map disabled controls parameter is Yes.  Proceeding with map of disabled controls.')

                    #Disable CIS 1.4 controls which are also disabled with CIS 1.2
                    #Confirm that CIS 1.2 standard is enabled in the account
                    enabled_standard=sh_client.get_enabled_standards(StandardsSubscriptionArns=['arn:aws:securityhub:{}:{}:{}'.format(aws_region, account, CIS12_standard)])
                
                    for enabled_standard in enabled_standard['StandardsSubscriptions']:
                        enabled_standard_arn = enabled_standard['StandardsArn']
                        enabled_standard_status = enabled_standard['StandardsStatus']
                        
                        if enabled_standard_status == 'READY':
                            print('CIS 1.2 is Enabled.  Proceeding with disabled control mapping.')

                            # If enabled then check to see if there are any disabled controls by getting a list of disabled
                            print('Checking for any disabled 1.2 controls')
                            standard_controls=sh_client.describe_standards_controls(StandardsSubscriptionArn='arn:aws:securityhub:{}:{}:{}'.format(aws_region, account, CIS12_standard))
                            
                            for control_list in standard_controls['Controls']:
                                control_id = control_list['ControlId']
                                control_status = control_list['ControlStatus']
                                
                                if control_status == 'DISABLED':
                                    print('--Disabled 1.2 control:', control_id)
                                    mapped_control = utils.get_control_map(control_id)
                                    
                                    if mapped_control:
                                        #Found a mapped control between 1.2 and 1.4.  Disable the mapped 1.4 control.
                                        print ('Mapped 1.4 control:', mapped_control)
                                        #disable the 1.4 control
                                        control_arn='arn:aws:securityhub:{}:{}:{}/{}'.format(aws_region, account, CIS_14_CONTROL_BASE,mapped_control.strip('CIS.'))
                                        print('Disabling the CIS 1.4 control')
                                        sh_client.update_standards_control(StandardsControlArn=control_arn, ControlStatus='DISABLED',
                                                                            DisabledReason='Aligning with CIS 1.2 disabled controls')
                                        #Sleep a few seconds so the api is not overwhelmed with multiple updates
                                        time.sleep(5)
                                    else:
                                        print('Disabled 1.2 control does not map to a 1.4 control.  Not disabling in 1.4')
                        
                        else:
                            print('CIS 1.2 is not enabled. Not doing any disabled control mapping.')


                #Disable CIS 1.2
                print('--------Disable CIS 1.2 step--------')
                if args.disable_cis12 == 'Yes':
                    print('Disabling CIS 1.2')
                    subscription_arn = 'arn:aws:securityhub:{}:{}:{}'.format(aws_region,account,CIS12_standard)
                    sh_client.batch_disable_standards(StandardsSubscriptionArns=[subscription_arn])
                    print("Finished disabling CIS 1.2 on account {} for region {}".format(account, aws_region))

                else:
                    print ('Not disabling CIS 1.2 standard')
    
        except ClientError as e:
            print("Error Processing Account {}".format(account))
            failed_accounts.append({
                account: repr(e)
            })

    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            for account_id, message in account.items():
                print("{}: \n\t{}".format(account_id, message))
        print("---------------------------------------------------------------")
