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
import sys
import time
import argparse
import re
import json
import random
import string
import utils

from collections import OrderedDict
from botocore.exceptions import ClientError
from six.moves import input as raw_input
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


def check_config(session,account, region, s3_bucket_name):
    config = session.client('config', region_name=region)
    iam = session.client('iam')
    s3 = session.client('s3', region_name='us-east-1')

    default_bucket_avail = False
    default_bucket_exists = False
    try: 
        iam.create_service_linked_role(AWSServiceName='config.amazonaws.com', Description='A service-linked role required for AWS Config')
    except ClientError as e:
        if e.response['ResponseMetadata']['HTTPStatusCode'] == 400:
            pass # SLR already exists
        else:
            print(e)
            return False
    # Check if default bucket name is available.
    try:
        s3.list_objects(Bucket='config-bucket-{}'.format(account), MaxKeys=1)
        default_bucket_exists = True
        s3_bucket_name = 'config-bucket-{}'.format(account)
    except ClientError as e:
        if e.response['ResponseMetadata']['HTTPStatusCode'] == 404:
            default_bucket_avail = True
            s3_bucket_name = 'config-bucket-{}'.format(account)
        pass
    if not len(config.describe_configuration_recorders()['ConfigurationRecorders']):
        config.put_configuration_recorder( ConfigurationRecorder={'name':'default','roleARN': 'arn:aws:iam::%s:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig' % account,'recordingGroup': {'allSupported' : True, 'includeGlobalResourceTypes': True}})
    
    if config.describe_configuration_recorder_status()['ConfigurationRecordersStatus'][0]['recording']:
        return True #config is configured and enabled nothing to do here.
    if len(config.describe_delivery_channels()['DeliveryChannels']):
        try: 
            config.start_configuration_recorder(ConfigurationRecorderName=config.describe_configuration_recorder_status()['ConfigurationRecordersStatus'][0]['name'])
            return True 
        except ClientError as e:
            print("Error {} starting configuration recorder for account {} in region {}".format(repr(e), account, region))
            return False
    ## Ensure S3 bucket for AWS Config delivery exists 
    if default_bucket_avail and not default_bucket_exists:
        try:
            s3.create_bucket(Bucket=s3_bucket_name) 
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSConfigBucketPermissionsCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": ["config.amazonaws.com"]},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::%s" % s3_bucket_name},
                    {
                        "Sid": " AWSConfigBucketDelivery",
                        "Effect": "Allow",
                        "Principal": {"Service": ["config.amazonaws.com"]},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::%s/AWSLogs/%s/Config/*" % (s3_bucket_name, account),
                        "Condition": { "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }}
                    }]
            }
            bucket_policy = json.dumps(bucket_policy)
            s3.put_bucket_policy(Bucket=s3_bucket_name, Policy=bucket_policy)
        except ClientError as e:
            print("Error {} checking bucket for Config delivery in account {}".format(repr(e), account))
            return False
    try:
        config.put_delivery_channel(DeliveryChannel={
            'name': 'config-s3-delivery', 
            's3BucketName': s3_bucket_name, 
            'configSnapshotDeliveryProperties': {'deliveryFrequency': 'TwentyFour_Hours' } 
            })
        config.start_configuration_recorder(ConfigurationRecorderName=config.describe_configuration_recorder_status()['ConfigurationRecordersStatus'][0]['name'])
        return True
    except ClientError as e:
        print("Error {} enabling Config on account {}".format(repr(e), account))
        return False
    return False
        
            
    


if __name__ == '__main__':
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Link AWS Accounts to central SecurityHub Account')
    parser.add_argument('--master_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('input_file', type=argparse.FileType('r'), help='Path to CSV file containing the list of account IDs and Email addresses')
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--enabled_regions', type=str, help="comma separated list of regions to enable SecurityHub. If not specified, all available regions enabled")
    parser.add_argument('--enable_standards', type=str, required=False,help="comma separated list of standards ARN resources to enable ( i.e. ruleset/cis-aws-foundations-benchmark/v/1.2.0 )")
    args = parser.parse_args()

    # Validate master accountId
    if not re.match(r'[0-9]{12}',args.master_account):
        raise ValueError("Master AccountId is not valid")
    
    # Generate dict with account & email information
    aws_account_dict = OrderedDict()
    
    # Notify on Config dependency if standards are enabled
    if args.enable_standards:
        print(
        '''
        *****************************************************************************************************************************************************************************************
        *      By turning on this Standards you will enable security evaluations to run. For current pricing and example scenarios please refer to the current AWS Security Hub pricing.        *
        *      Important: You must enable AWS Config for all resources in each AWS Region where you will be running a Standard. If Config is not already enabled it will be enabled and         *
        *      configured in each region.                                                                                                                                                       *
        *                                                                                                                                                                                       *
        *      In addition to AWS Security Hub charges, you will also incur charges for the Configuration Items recorded by AWS Config, as per the AWS Config pricing. These charges are        *
        *      separate from (and not included in) AWS Security Hub pricing.                                                                                                                    *
        *****************************************************************************************************************************************************************************************
        
        Continue?(yes/no):
        '''
        )
        notify_config_response = ''
        response = raw_input(notify_config_response).lower()
        if 'yes' != response and 'y' != response:
            print("Exiting..")
            raise SystemExit(0)
     
    for acct in args.input_file.readlines():
        split_line = acct.rstrip().split(",")
        if len(split_line) < 2:
            print("Unable to process line: {}".format(acct))
            continue
            
        if not re.match(r'[0-9]{12}', str(split_line[0])):
            print("Invalid account number {}, skipping".format(split_line[0]))
            continue
            
        aws_account_dict[split_line[0]] = split_line[1]

    # Check length of accounts to be processed
    if len(aws_account_dict.keys()) > 1000:
        raise Exception("Only 1000 accounts can be linked to a single master account")
    
    # Getting SecurityHub regions
    session = boto3.session.Session()

    securityhub_regions = []
    if args.enabled_regions:
        securityhub_regions = [str(item) for item in args.enabled_regions.split(',')]
        print("Enabling members in these regions: {}".format(securityhub_regions))
    else:
        securityhub_regions = session.get_available_regions('securityhub')
        print("Enabling members in all available SecurityHub regions {}".format(securityhub_regions))
    
    # Check if enable Standards 
    standards_arns = []
    if args.enable_standards:
        standards_arns = [str(item) for item in args.enable_standards.split(',')]
        print("Enabling the following Security Hub Standards for enabled account(s) and region(s): {}".format(standards_arns))


    # Processing Master account
    master_session = assume_role(args.master_account, args.assume_role)
    #master_session = boto3.Session()
    master_clients = {}
    members = {}
    for aws_region in securityhub_regions:
        master_clients[aws_region] = master_session.client('securityhub', region_name=aws_region)
        try: 
            # Enable Security Hub for the Master Account 
            master_clients[aws_region].enable_security_hub()

            # Enable compliance Standards for Master account 
            compliance_standards_arns = [utils.get_standard_arn_for_region_and_resource(aws_region, standard) for standard in standards_arns]
            batch_enable_standards_input = [{'StandardsArn': standard_arn} for standard_arn in compliance_standards_arns]
            master_clients[aws_region].batch_enable_standards(StandardsSubscriptionRequests=batch_enable_standards_input)

            # Verify standards get enabled in the Master Account 
            standards_to_verify = compliance_standards_arns[:]
            standards_status = {}
            start_time = int(time.time())
            while len(standards_to_verify) > 0:
                if (int(time.time()) - start_time) > 100:
                    print("Timeout waiting for READY state enabling standards {standards} in region {region} for account {account}, last state: {status}"
                          .format(standards=compliance_standards_arns, region=aws_region, account=args.master_account, status=standards_status))
                    break
                enabled_standards = master_clients[aws_region].get_enabled_standards()
                for enabled_standard in enabled_standards['StandardsSubscriptions']:
                    enabled_standard_arn = enabled_standard['StandardsArn']
                    enabled_standard_status = enabled_standard['StandardsStatus']
                    standards_status[enabled_standard_arn] = enabled_standard_status
                    if enabled_standard_arn in standards_to_verify and enabled_standard_status == 'READY':
                        print("Finished enabling stanard {} on account {} for region {}".format(enabled_standard_arn, args.master_account, aws_region))
                        standards_to_verify.remove(enabled_standard_arn)


        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceConflictException':
                pass
            else:
                print("Error: Unable to enable Security Hub on Master account in region {}".format(aws_region))
                raise SystemExit(0)

        members[aws_region] = get_master_members(master_clients[aws_region], aws_region)

    # Processing accounts to be linked
    failed_accounts = []
    for account in aws_account_dict.keys():
        if account == args.master_account:
            print("Won't try to link master account %s to itself" % account)

        try:

            session = assume_role(account, args.assume_role)
            # Generate unique bucket name for Config delivery channel if default is not avaialable.
            s3_bucket_name = 'config-bucket-{}-{}'.format(''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(5)), account)
            
            for aws_region in securityhub_regions:
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))
                
                sh_client = session.client('securityhub', region_name=aws_region)
                #Ensure AWS Config is enabled for the account/region and enable if it not already enabled.
                config_result = check_config(session, account, aws_region, s3_bucket_name)
                if not config_result:
                    failed_accounts.append({account: "Error validating or enabling AWS Config for account {} in {} - requested standards not enabled".format(account,aws_region)})
                else:
                    try:
                        sh_client.enable_security_hub()
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ResourceConflictException':
                            pass

                    if args.enable_standards:
                        regional_standards_arns = [utils.get_standard_arn_for_region_and_resource(aws_region, standard) for standard in standards_arns]
                        batch_enable_standards_input = [{'StandardsArn': standard_arn} for standard_arn in regional_standards_arns]
                        sh_client.batch_enable_standards(StandardsSubscriptionRequests=batch_enable_standards_input)

                        # Verify standards get enabled
                        standards_to_verify = regional_standards_arns[:]
                        standards_status = {}
                        start_time = int(time.time())
                        while len(standards_to_verify) > 0:
                            if (int(time.time()) - start_time) > 100:
                                print("Timeout waiting for READY state enabling standards {standards} in region {region} for account {account}, last state: {status}"
                                      .format(standards=regional_standards_arns, region=aws_region, account=account, status=standards_status))
                                break
                            enabled_standards = sh_client.get_enabled_standards()
                            for enabled_standard in enabled_standards['StandardsSubscriptions']:
                                enabled_standard_arn = enabled_standard['StandardsArn']
                                enabled_standard_status = enabled_standard['StandardsStatus']
                                standards_status[enabled_standard_arn] = enabled_standard_status
                                if enabled_standard_arn in standards_to_verify and enabled_standard_status == 'READY':
                                    print("Finished enabling stanard {} on account {} for region {}".format(enabled_standard_arn,account, aws_region))
                                    standards_to_verify.remove(enabled_standard_arn)


                if account in members[aws_region]:
                    print('Account {monitored} is already a member of {master} in region {region}'.format(
                        monitored=account,
                        master=args.master_account,
                        region=aws_region
                    ))
                else:
                    master_clients[aws_region].create_members(
                        AccountDetails=[{
                            "AccountId": account,
                            "Email": aws_account_dict[account]
                        }]
                    )

                    print('Added Account {monitored} to member list in SecurityHub master account {master} for region {region}'.format(
                        monitored=account,
                        master=args.master_account,
                        region=aws_region
                    ))

                    start_time = int(time.time())
                    while account not in members[aws_region]:
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

                if account not in members[aws_region]:
                    print("Account {} could not be joined, skipping".format(account))
                    continue

                if members[aws_region][account] == 'Associated':
                    # Member is enabled and already being monitored
                    print('Account {account} is already enabled'.format(account=account))

                else:
                    start_time = int(time.time())
                    while members[aws_region][account] != 'Associated':
                        if (int(time.time()) - start_time) > 300:
                            print("Invitation did not show up for account {}, skipping".format(account))
                            failed_accounts.append({
                                account: "Membership did not show up for account {} in {}".format(
                                    account,
                                    aws_region
                                )
                            })
                            break

                        if members[aws_region][account] == 'Created':
                            # Member has been created in the SecurityHub master account but not invited yet
                            master_clients[aws_region].invite_members(
                                AccountIds=[account]
                            )

                            print('Invited Account {monitored} to SecurityHub master account {master} in region {region}'.format(
                                monitored=account,
                                master=args.master_account,
                                region=aws_region
                            ))

                        if members[aws_region][account] == 'Invited':
                            # member has been invited so accept the invite

                            response = sh_client.list_invitations()

                            invitation_dict = dict()

                            invitation_id = None
                            for invitation in response['Invitations']:
                                invitation_id = invitation['InvitationId']

                            if invitation_id is not None:
                                sh_client.accept_invitation(
                                    InvitationId=invitation_id,
                                    MasterId=str(args.master_account)
                                )
                                print('Accepting Account {monitored} to SecurityHub master account {master} in region {region}'.format(
                                    monitored=account,
                                    master=args.master_account,
                                    region=aws_region
                                ))

                        # Refresh the member dictionary
                        members[aws_region] = get_master_members(master_clients[aws_region], aws_region)

                    print('Finished {account} in {region}'.format(account=account, region=aws_region))
                    
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
