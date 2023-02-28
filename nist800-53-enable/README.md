## AWS Security Hub multi-account NIST 800-53 enable script

These scripts automate the process of enabling the NIST 800-53 security standard across a group of AWS accounts that are in your control. (Note, that you can have one administrator account and up to a 5000 member accounts).

The **enableNIST800-53.py** script will do the following for each account and region provided to the script:
* Enable NIST 800-53 security standard.



## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Prerequisites

* The script depends on a pre-existing role in the admin account and all of the member accounts that will be accessed.  The role name must be the same in all accounts and the role trust relationship needs to allow your instance or local credentials to assume the role.  The policy document below contains the required permissions for the script to succeed:

``` 
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "securityhub:BatchEnableStandards",
                "securityhub:BatchDisableStandards",
                "securityhub:GetEnabledStandards",
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
```

If you do not have a common role that includes at least the above permissions you will need to create a role in each member account as well as the administrative account with at least the above permissions.  When creating the role ensure you use the same role name in every account.  You can use the **enable-NIST800-53.yaml** CloudFormation template to automate this process.  This template creates a role named: **ManageSecurityHubNIST**.  The template creates only global resources so it can be created in any region.    

* A text file that includes the list of accounts where the NIST 800-53 standard needs to be enabled.  Each account should be listed on its own line in the file.

## Steps
### 1. Setup execution environment:
#### Option 1: Launch EC2 instance:
* Launch ec2 instance in your master account https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to an instance that has permissions to allow the instance to call AssumeRole within the master account, if you used the **enable-NIST800-53.yaml** template an instance role with a profile name of **EnableSecurityHubNIST** has been created, otherwise see the documentation on creating an instance role here:  https://aws.amazon.com/blogs/security/easily-replace-or-attach-an-iam-role-to-an-existing-ec2-instance-by-using-the-ec2-console/ on creating an instance role.
* Install required software
    * APT: sudo apt-get -y install python3-pip python3 git
    * RPM: sudo yum -y install python3-pip python3 git
    * sudo pip install boto3
* Clone the Repository
    * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
    * cd aws-securityhub-multiaccount-scripts/nist800-53-enable
* Copy the text file containing the account numbers to the instance using one of the methods below
    * S3 `s3 cp s3://bucket/key_name enable.txt .`
    * pscp.exe `pscp local_file_path username@hostname:.`
    * scp `scp local_file_path username@hostname:.`

#### Option 2: Locally:
* Ensure you have credentials setup on your local machine for your master account that have permission to call AssumeRole.
* Install Required Software:
    * Windows:
        * Install Python https://www.python.org/downloads/windows/
        * Open command prompt:
            * pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/nist800-53-enable
    * Mac:
        * Install Python https://www.python.org/downloads/mac-osx/
        * Open command prompt:
            * pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/nist800-53-enable
    * Linux:
        * sudo apt-get -y install install python2-pip python2 git
        * sudo pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/nist800-53-enable
        
        Or
        
        * sudo yum install git python
        * sudo pip install boto3
        * git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git
        * cd aws-securityhub-multiaccount-scripts/nist800-53-enable

### 2. Execute Scripts
#### 2a. Enable NIST800-53
* Copy the required txt file to this directory
    * Should be a format where each account number is listed on a line.

```
usage: enableNIST800-53.py [-h] --assume_role ASSUME_ROLE 
                                --enabled_regions ENABLED_REGIONS
                                --input_file PATH_TO_ACCOUNTS_FILE

Enable NIST 800-53 in Security Hub accounts

                        
required arguments:
  -h, --help            show this help message and exit
  
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account.
  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to enable the NIST 800-53 standard in.
                        If not specified, all available regions are enabled.

  --input_file INPUT_FILE
                        Path to the txt file containing the list of account IDs.
  
  
```

```
Example usage:
$ python3 enableNIST800-53.py --assume_role ManageSecurityHubNIST --enabled_regions us-west-2,us-east-1 --input_file /home/ec2-user/accounts.txt
```

#### 2b. Disable NIST800-53
* Copy the required txt file to this directory
    * Should be a format where each account number is listed on a line.

```
usage: disableNIST800-53.py [-h] --assume_role ASSUME_ROLE 
                                 --enabled_regions ENABLED_REGIONS
                                 --input_file PATH_TO_ACCOUNTS_FILE

Disable NIST 800-53 in Security Hub accounts

                        
required arguments:
  -h, --help            show this help message and exit
  
  --assume_role ASSUME_ROLE
                        Role Name to assume in each account.
  --enabled_regions ENABLED_REGIONS
                        comma separated list of regions to disable the NIST 800-53 standard in.
                        If not specified, all available regions are enabled.

  --input_file INPUT_FILE
                        Path to the txt file containing the list of account IDs.
  
  
```

```
Example usage:
$ python3 disableNIST800-53.py --assume_role ManageSecurityHubNIST --enabled_regions us-west-2,us-east-1 --input_file /home/ec2-user/accounts.txt