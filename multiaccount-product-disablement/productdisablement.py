#!/usr/bin/env python
"""
Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.

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

from collections import OrderedDict
from botocore.exceptions import ClientError


def assume_role(aws_account_id, role_name):
    """
    Assumes the provided role in each account and returns a Security Hub CSPM client
    :param aws_account_id: AWS Account ID
    :param role_name: Role to assume in target account
    :return: boto3 Session object
    """
    
    sts_client = boto3.client('sts')
    
    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    
    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_id,
            role_name
        ),
        RoleSessionName='DisableSecurityHubCSPMProducts'
    )
    
    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for {}.".format(aws_account_id))

    return session


def get_admin_members(sh_client, aws_region):
    """
    Returns a dict of current members of the Security Hub Administrator account
    :param sh_client: SecurityHub client
    :param aws_region: AWS Region of the Security Hub Administrator account
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


if __name__ == '__main__':
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Disable Security Hub CSPM product integrations across multiple AWS accounts')
    parser.add_argument('input_file', nargs='?', type=argparse.FileType('r'), help='Optional: Path to CSV file containing account IDs (one per line). If not provided, uses all Security Hub member accounts')
    parser.add_argument('--assume_role_name', type=str, required=True, help="Role Name to assume in each account")
    parser.add_argument('--regions-to-disable', type=str, required=True, help="Comma separated list of regions to disable products, or 'ALL' for all available regions (format: us-east-1, eu-west-1, etc.)")
    parser.add_argument('--products', type=str, required=True, help="Comma separated list of product identifiers to disable (e.g., 'aws/guardduty,aws/macie' or product ARNs)")
    parser.add_argument('--dry-run', action='store_true', help="Preview changes without actually disabling products. Shows what would be disabled.")
    args = parser.parse_args()
    
    # Parse product list
    product_identifiers = [str(item).strip() for item in args.products.split(',')]
    print("Products to disable: {}".format(product_identifiers))
    
    # Display dry-run mode status
    if args.dry_run:
        print("\n" + "="*70)
        print("DRY-RUN MODE ENABLED")
        print("="*70)
        print("NO CHANGES WILL BE MADE - This is a preview only")
        print("Products will NOT actually be disabled")
        print("Run without --dry-run flag to execute changes")
        print("="*70 + "\n")
    
    # Getting Security Hub regions
    session = boto3.session.Session()
    
    securityhub_regions = []
    if args.regions_to_disable.upper() == 'ALL':
        securityhub_regions = session.get_available_regions('securityhub')
        print("Will check for members in all available Security Hub CSPM regions: {}".format(securityhub_regions))
    else:
        securityhub_regions = [str(item).strip() for item in args.regions_to_disable.split(',')]
        
        # Validate against actual available Security Hub regions
        # This covers standard, GovCloud (us-gov-*), China (cn-*), and ISO (us-iso-*) regions
        available_regions = session.get_available_regions('securityhub')
        invalid_regions = [r for r in securityhub_regions if r not in available_regions]
        
        if invalid_regions:
            print("ERROR: Invalid or unavailable Security Hub regions: {}".format(invalid_regions))
            print("Available regions: {}".format(', '.join(sorted(available_regions))))
            exit(1)
        
        print("Will check for members in these regions: {}".format(securityhub_regions))
    
    # Get the DA account ID and partition (needed for both CSV and non-CSV modes)
    sts_client = session.client('sts')
    caller_identity = sts_client.get_caller_identity()
    da_account_id = caller_identity['Account']
    partition = caller_identity['Arn'].split(":")[1]
    print("Detected partition: {}".format(partition))
    
    # Initialize members dict for all regions
    members = {}
    for aws_region in securityhub_regions:
        members[aws_region] = {}
    
    # If CSV file provided, read account IDs from it
    if args.input_file:
        print("CSV file provided - will process accounts from CSV")
        csv_accounts = set()
        for acct in args.input_file.readlines():
            split_line = acct.rstrip().split(",")
            if len(split_line) < 1:
                print("Unable to process line: {}".format(acct))
                continue
            
            account_id = split_line[0].strip()
            
            if not re.match(r'[0-9]{12}', account_id):
                print("Invalid account number {}, skipping".format(account_id))
                continue
                
            csv_accounts.add(account_id)
        
        # Use CSV accounts directly (no member fetching needed)
        accounts_to_process = csv_accounts
        
        # Populate members dict to pass membership check during processing
        for aws_region in securityhub_regions:
            for account in csv_accounts:
                members[aws_region][account] = 'CSV_PROVIDED'
        
        print("Processing {} accounts from CSV file".format(len(accounts_to_process)))
            
    else:
        # No CSV provided - fetch and use all member accounts + DA account
        print("No CSV file provided - will fetch all Security Hub member accounts")
        
        # Get Security Hub member accounts from all regions (only when needed)
        admin_clients = {}
        all_member_accounts = set()
        
        for aws_region in securityhub_regions:
            admin_clients[aws_region] = session.client('securityhub', region_name=aws_region)
            try:
                members[aws_region] = get_admin_members(admin_clients[aws_region], aws_region)
                all_member_accounts.update(members[aws_region].keys())
                print("Found {} member accounts in region {}".format(len(members[aws_region]), aws_region))
            except ClientError as e:
                print("Error listing members in region {}: {}".format(aws_region, repr(e)))
                members[aws_region] = {}
        
        print("Total unique Security Hub CSPM member accounts across all regions: {}".format(len(all_member_accounts)))
        
        accounts_to_process = all_member_accounts.copy()
        
        # Add the DA (Delegated Administrator) account to the list and to members dict
        accounts_to_process.add(da_account_id)
        # Add DA account to members dict for all regions so it doesn't get skipped
        for aws_region in securityhub_regions:
            members[aws_region][da_account_id] = 'DA_ACCOUNT'
        print("Added DA account {} to the list for processing".format(da_account_id))
    
    if len(accounts_to_process) == 0:
        print("ERROR: No accounts to process. Exiting.")
        exit(1)
    
    print("Total accounts to process: {}".format(len(accounts_to_process)))
    print("Disabling products in regions: {}".format(securityhub_regions))
    
    # Processing accounts
    failed_accounts = []
    for account in sorted(accounts_to_process):
        try:
            # For DA account, use current session; for others, assume role
            if account == da_account_id:
                print("Using current session for DA account {}.".format(account))
                account_session = boto3.session.Session()
            else:
                account_session = assume_role(account, args.assume_role_name)
            
            for aws_region in securityhub_regions:
                # Check if account is a member in this specific region
                if account not in members[aws_region]:
                    print('Account {account} is not a Security Hub CSPM member in region {region} - skipping'.format(
                        account=account,
                        region=aws_region
                    ))
                    continue
                
                print('Beginning {account} in {region}'.format(
                    account=account,
                    region=aws_region
                ))
                
                try:
                    sh_client = account_session.client('securityhub', region_name=aws_region)
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'UnrecognizedClientException':
                        print('  [SKIP] Region not enabled for account: {}'.format(aws_region))
                        continue
                    else:
                        print('  [FAIL] {}'.format(repr(e)))
                        failed_accounts.append({
                            account: "Failed to create client in {}".format(aws_region)
                        })
                        continue
                
                # Directly disable specified products (idempotent - safe if already disabled)
                for product_identifier in product_identifiers:
                    try:
                        # Construct ProductSubscriptionArn with correct partition
                        # Format: arn:{partition}:securityhub:region:account-id:product-subscription/provider/product
                        # Supports: aws, aws-us-gov, aws-cn, aws-iso, aws-iso-b
                        product_arn = 'arn:{partition}:securityhub:{region}:{account}:product-subscription/{product}'.format(
                            partition=partition,
                            region=aws_region,
                            account=account,
                            product=product_identifier
                        )
                        
                        if args.dry_run:
                            print('  [DRY-RUN] Would disable product {product} in account {account} region {region}'.format(
                                product=product_identifier,
                                account=account,
                                region=aws_region
                            ))
                        else:
                            sh_client.disable_import_findings_for_product(
                                ProductSubscriptionArn=product_arn
                            )
                            print('  Disabled product {product} in account {account} region {region}'.format(
                                product=product_identifier,
                                account=account,
                                region=aws_region
                            ))
                        
                    except ClientError as e:
                        error_code = e.response['Error']['Code']
                        error_message = e.response['Error'].get('Message', '')
                        
                        # Skip expected cases
                        if error_code == 'ResourceNotFoundException':
                            print('  [SKIP] Product not enabled: {}'.format(product_identifier))
                        elif error_code == 'InvalidAccessException' and ('not subscribed to AWS Security Hub' in error_message or 'SecurityHub is not enabled' in error_message.lower()):
                            print('  [SKIP] Security Hub not enabled')
                        elif error_code == 'UnrecognizedClientException':
                            print('  [SKIP] Region not enabled for account: {}'.format(aws_region))
                            break  # Skip remaining products for this region
                        else:
                            # Everything else - print the raw error
                            print('  [FAIL] {}'.format(repr(e)))
                            failed_accounts.append({
                                account: "{} in {}".format(product_identifier, aws_region)
                            })
                
                print('Finished {account} in {region}'.format(account=account, region=aws_region))
                    
        except ClientError as e:
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            print("[FAIL] Account {}: {}".format(account, error_msg))
            failed_accounts.append({
                account: error_msg
            })

    if len(failed_accounts) > 0:
        print("---------------------------------------------------------------")
        print("Failed Accounts")
        print("---------------------------------------------------------------")
        for account in failed_accounts:
            for account_id, message in account.items():
                print("{}: \n\t{}".format(account_id, message))
        print("---------------------------------------------------------------")
