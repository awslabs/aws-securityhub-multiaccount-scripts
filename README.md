## AWS Security Hub Multiaccount Scripts

These scripts automate the process of enabling and disabling Amazon Security Hub simultaneously across a group of AWS accounts that are in your control. (Note, that you can have one master account and up to a 1000 member accounts).

enablesecurityhub.py will enable Security Hub, send invitations from the master account and accept invitations in all member accounts. The result will be a master account that contains all security findings for all member accounts. Since Security Hub is regionally isolated, findings for each member account will roll up to the corresponding region in the master account. For example, the us-east-1 region in your Security Hub master account will contain the security findings for all us-east-1 findings from all associated member accounts.

Note: Account owners of member accounts will recieve an email for each region requesting that they accept the invitation to link their accounts, these emails can be ignored as the script accepts the inventation on their behalf.


## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Prerequisites

* The scripts depend on a pre-existing role in the master account and all of the member accounts that will be linked, the role name must be the same in all accounts and the role trust relationship needs to allow your instance or local credentials to assume the role.  The AmazonSecurityHubFullAccess managed poilicy (shown below) contains the required permissions for the script to succeed:

``` 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "securityhub:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "securityhub.amazonaws.com"
                }
            }
        }
    ]
}
```

If you do not have a common role that includes at least the above permissions you will need to create a role in each member account as well as the master account with at least the above permissions.  When creating the role ensure you use the same role name in every account and select the AmazonSecurityHubFullAccess managed policy.  You can use the EnableSecurityHub.yaml CloudFormation Template to automate this process, as the tempalte creates only global resources it can be created in any region.    

* A CSV file that includes the list of accounts to be linked to the master account.  Accounts should be listed one per line in the format of AccountId,EmailAddress.  The EmailAddress must be the email associated with the root account.
* Master AccountId which will recieve findings for all the linked accounts within the CSV file 

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* Launch ec2 instance in your master account https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to an instance that has permissions to allow the instance to call AssumeRole within the master account, if you used the EnableSecurityHub.yaml template an instance role with a profile name of "EnableSecurityHub" has been created, otherwise see the documentation on creating an instance role here:  https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/ on creating an instance role.
* Install required software
    * APT: sudo apt-get -y install python2-pip python2 git
    * RPM: sudo yum -y install python2-pip python2 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/aws-samples/amazon-securityhub-multiaccount-scripts.git
* Copy the CSV containing the account number and email addresses to the instance using one of the methods below
    * S3 `s3 cp s3://bucket/key_name enable.csv .`
    * pscp.exe `pscp local_file_path username@hostname:.`
    * scp `scp local_file_path username@hostname:.`

#### Option 2: Locally:
* Ensure you have credentials setup on your local machine for your master account that have permission to call AssumeRole.
* Install Required Software:
    * Windows:
        * Install Python https://www.python.org/downloads/windows/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-securityhub-multiaccount-scripts
        * Change directory of command prompt to the newly downloaded amazon-securityhub-multiaccount-scripts folder
    * Mac:
        * Install Python https://www.python.org/downloads/mac-osx/
        * Open command prompt:
            * pip install boto3
        * Download sourcecode from https://github.com/aws-samples/amazon-securityhub-multiaccount-scripts
        * Change directory of command prompt to the newly downloaded amazon-securityhub-multiaccount-scripts folder
    * Linux:
        * sudo apt-get -y install install python2-pip python2 git
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-securityhub-multiaccount-scripts
        * cd amazon-securityhub-multiaccount-scripts
        Or
        * sudo yum install git python
        * sudo pip install boto3
        * git clone https://github.com/aws-samples/amazon-securityhub-multiaccount-scripts
        * cd amazon-securityhub-multiaccount-scripts

### 2. Execute Scripts
#### 2a. Enable Security Hub
* Copy the required CSV file to this directory
    * Should be in the formation of "AccountId,EmailAddress" with one AccountID and EmailAddress per line.

```
usage: enablesecurityhub.py [-h] --master_account MASTER_ACCOUNT --assume_role
                          ASSUME_ROLE
                          input_file

Link AWS Accounts to central Security Hub Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs
                        and Email addresses

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  
```
    
#### 2b. Disable Security Hub
* Copy the required CSV file to this directory
    * Should be in the formation of "AccountId,EmailAddress,..."

```
usage: disablesecurityhub.py [-h] --master_account MASTER_ACCOUNT --assume_role
                           ASSUME_ROLE [--delete_master]
                           input_file

Link AWS Accounts to central Security Hub Account

positional arguments:
  input_file            Path to CSV file containing the list of account IDs
                        and Email addresses

optional arguments:
  -h, --help            show this help message and exit
  --master_account MASTER_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account
  --delete_master       Delete the master Gd Detector
```
