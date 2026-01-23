# AWS Security Hub Multi-Account Product Disablement Script

## Overview

This script automates the process of disabling specific AWS Security Hub CSPM product integrations across multiple AWS accounts in an AWS Organization. It must be run from the Security Hub CSPM Delegated Administrator account.

## License Summary

This sample code is made available under a modified MIT license. See the LICENSE file.

## Account Roles

This script works in an AWS Organizations setup with Security Hub CSPM enabled, using a Delegated Administrator account model:

**Security Hub CSPM Delegated Administrator Account:**
- This is where you RUN the script
- The account designated as the Delegated Administrator for Security Hub CSPM in your AWS Organization
- Has organizational visibility into all Security Hub CSPM member accounts
- Can list members and assume roles in member accounts
- Example: Your central security/compliance account

**Member Accounts:**
- These are the accounts where products will be DISABLED
- Organization member accounts that are enabled for Security Hub CSPM
- Must have an IAM role that trusts the Delegated Administrator account
- Example: Your application accounts, workload accounts, sandbox accounts

## Prerequisites

### Delegated Administrator (DA) Account

The role that runs the script from, in the DA account, must have these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:ListMembers",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

This allows the DA account to:
- List all Security Hub member accounts
- Assume roles in member accounts to disable products

### Member Accounts (Target Accounts)

Each member account must have an IAM role with:

1. **IAM permissions** to disable products:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:DisableImportFindingsForProduct"
            ],
            "Resource": "*"
        }
    ]
}
```

2. **Trust policy** that grants the DA account permission to assume this role:
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::DA_ACCOUNT_ID:root"
        },
        "Action": "sts:AssumeRole"
    }]
}
```

**Important:** 
- The role name must be the same in ALL member accounts (e.g., `SecurityHubRole`)
- Replace `DA_ACCOUNT_ID` with your actual DA account ID
- The trust policy is what grants the DA account STS access to assume the role

### Quick Setup Summary

1. **In DA Account (where you run the script):**
   - Attach permissions: `securityhub:ListMembers`, `sts:AssumeRole`

2. **In Each Member Account (where products will be disabled):**
   - Create IAM role named `SecurityHubRole`
   - Attach permission: `securityhub:DisableImportFindingsForProduct`
   - Set trust policy to allow DA account to assume the role (grants STS access)

**Note:** The script will only process accounts that are Security Hub members of the Delegated Administrator account.

### Optional: CSV File

A CSV file with account IDs to process. Accounts should be listed one per line with the account ID.
- If CSV is provided: Script processes **accounts from the CSV file**
- If CSV is not provided: Script processes **all Security Hub member accounts**

### Software Requirements

Python 2.7+ or Python 3.x with boto3 library installed

## Troubleshooting: STS Regional Endpoint Configuration (Optional)

If you encounter STS-related errors when running the script, you may need to configure regional STS endpoints.

### Symptoms

You might see errors like:

```
AccessDenied when calling GetCallerIdentity operation: 
You are currently using the legacy global endpoint. 
Please switch to the regional endpoint instead.
```

### Solution

If you encounter this error, configure regional STS endpoints:

**Temporary fix (current session only):**
```bash
export AWS_STS_REGIONAL_ENDPOINTS=regional
export AWS_DEFAULT_REGION=<preferred_region>
```

**Permanent fix (recommended):**

Add to your `~/.aws/config` file:

```ini
[default]
sts_regional_endpoints = regional
region = us-east-1  # or your preferred region
```

Or use this command:

```bash
cat >> ~/.aws/config << 'EOF'

[default]
sts_regional_endpoints = regional
EOF
```

**What it does:** This setting tells the AWS SDK to use regional STS endpoints (e.g., `sts.us-east-1.amazonaws.com`) instead of the legacy global endpoint (`sts.amazonaws.com`).

For more information: [AWS STS Regionalized Endpoints Documentation](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html)

## Creating the IAM Role

The necessary IAM role for member accounts can be created in each account individually via the AWS CLI, or deployed in bulk across all member accounts via CloudFormation StackSets. Choose the method that best fits your organization:

- **[CLI Method](#cli-method)** - For individual accounts or small-scale deployments
- **[CloudFormation StackSets Method](#automated-role-deployment-using-cloudformation-stacksets-recommended-for-large-organizations)** - For bulk deployment across multiple accounts (recommended for large organizations)

### CLI Method

If the SecurityHubRole doesn't exist in your member accounts, create it using the AWS CLI:

```bash
# Run these commands in EACH MEMBER ACCOUNT (not the DA account)

# 1. Create trust policy
# Replace 123456789012 with your DA account ID (where you run the script)
cat > trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::123456789012:root"
        },
        "Action": "sts:AssumeRole"
    }]
}
EOF

# 2. Create IAM policy
cat > iam-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "securityhub:DisableImportFindingsForProduct"
        ],
        "Resource": "*"
    }]
}
EOF

# 3. Create role
aws iam create-role \
    --role-name SecurityHubRole \
    --assume-role-policy-document file://trust-policy.json

# 4. Attach policy
aws iam put-role-policy \
    --role-name SecurityHubRole \
    --policy-name SecurityHubProductManagement \
    --policy-document file://iam-policy.json
```

**Note:** The trust policy (step 1) grants the DA account STS access to assume this role. This is required for cross-account access.

## Automated Role Deployment Using CloudFormation StackSets (Recommended for Large Organizations)

### Overview

For organizations with hundreds or thousands of member accounts, manually creating IAM roles in each account is impractical. **CloudFormation StackSets** provides an automated solution to deploy the required IAM role across all member accounts simultaneously from your AWS Organizations management account.

### Prerequisites

1. **Access to Management Account** - You need administrative access to your AWS Organizations management account
2. **Organizations Integration** - CloudFormation StackSets must have trusted access enabled with AWS Organizations
3. **DA Account ID** - Know your Security Hub CSPM Delegated Administrator account ID

### Step 1: Enable StackSets with Organizations (One-Time Setup)

This step only needs to be done once for your organization.

#### Option A: AWS Console (Recommended)

1. Log into your **Management Account**
2. Navigate to: **CloudFormation → StackSets** (https://console.aws.amazon.com/cloudformation/home#/stacksets)
3. If prompted, click **"Enable trusted access with AWS Organizations"**
4. Confirmation: You should see StackSets enabled

#### Option B: AWS CLI

```bash
# Enable trusted access
aws organizations enable-aws-service-access \
    --service-principal member.org.stacksets.cloudformation.amazonaws.com

# Verify it's enabled
aws organizations list-aws-service-access-for-organization \
    --query 'EnabledServicePrincipals[?ServicePrincipal==`member.org.stacksets.cloudformation.amazonaws.com`]'
```

### Step 2: Use the CloudFormation Template

The CloudFormation template is provided in this directory as `SecurityHubRole-StackSet.yaml`. This template:
- Creates an IAM role named `SecurityHubRole` in each member account
- Configures the trust policy to allow your DA account to assume the role
- Attaches the necessary Security Hub permissions
- Tags resources for tracking

**Template file:** `SecurityHubRole-StackSet.yaml` (included in this directory)

### Step 3: Deploy the StackSet

Replace `YOUR_DA_ACCOUNT_ID` with your actual Delegated Administrator account ID:

```bash
# Create the StackSet
aws cloudformation create-stack-set \
    --region us-east-1 \
    --stack-set-name SecurityHubRoleDeployment \
    --template-body file://SecurityHubRole-StackSet.yaml \
    --description "Deploy SecurityHub role to all member accounts" \
    --parameters ParameterKey=DelegatedAdminAccountId,ParameterValue=YOUR_DA_ACCOUNT_ID \
    --permission-model SERVICE_MANAGED \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --capabilities CAPABILITY_NAMED_IAM
```

Expected output:
```json
{
    "StackSetId": "SecurityHubRoleDeployment:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### Step 4: Deploy to All Member Accounts

#### Option A: Deploy to Entire Organization

```bash
# Get your root organizational unit ID
ROOT_OU=$(aws organizations list-roots --region us-east-1 --query 'Roots[0].Id' --output text)

# Deploy to all accounts in the organization
aws cloudformation create-stack-instances \
    --region us-east-1 \
    --stack-set-name SecurityHubRoleDeployment \
    --deployment-targets OrganizationalUnitIds=$ROOT_OU \
    --regions us-east-1 \
    --operation-preferences MaxConcurrentPercentage=20,FailureTolerancePercentage=5
```

#### Option B: Deploy to Specific Organizational Unit

```bash
# List your OUs to find the right one
aws organizations list-organizational-units-for-parent --parent-id $ROOT_OU

# Deploy to specific OU
aws cloudformation create-stack-instances \
    --region us-east-1 \
    --stack-set-name SecurityHubRoleDeployment \
    --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
    --regions us-east-1
```

#### Option C: Deploy to Specific Accounts (Testing)

```bash
# Deploy to specific test accounts only
aws cloudformation create-stack-instances \
    --region us-east-1 \
    --stack-set-name SecurityHubRoleDeployment \
    --deployment-targets OrganizationalUnitIds=$ROOT_OU,AccountFilterType=INTERSECTION,Accounts=111111111111,222222222222 \
    --regions us-east-1
```

Expected output:
```json
{
    "OperationId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### Step 5: Verify and Use

1. **Run the product disablement script** as normal:
```bash
python3 productdisablement.py \
    --assume_role_name SecurityHubRole \
    --regions-to-disable us-east-1 \
    --products aws/guardduty
```

## Script Execution Steps

### 1. Setup Execution Environment

#### Option 1: Launch EC2 Instance
* Launch an EC2 instance https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EC2_GetStarted.html
* Attach an IAM role to the instance that has permissions to call AssumeRole for the target accounts
* Install required software:
    * APT: `sudo apt-get -y install python-pip python git`
    * RPM: `sudo yum -y install python-pip python git`
    * `sudo pip install boto3`
* Clone the repository:
    * `git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git`
    * `cd aws-securityhub-multiaccount-scripts/multiaccount-product-disablement`
* Copy your CSV file to the instance

#### Option 2: Run Locally
* Ensure you have credentials configured on your local machine that have permission to call AssumeRole
* Install required software:
    * **Windows:**
        * Install Python https://www.python.org/downloads/windows/
        * `pip install boto3`
        * `git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git`
        * `cd aws-securityhub-multiaccount-scripts\multiaccount-product-disablement`
    * **Mac:**
        * Install Python https://www.python.org/downloads/mac-osx/
        * `pip install boto3`
        * `git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git`
        * `cd aws-securityhub-multiaccount-scripts/multiaccount-product-disablement`
    * **Linux:**
        * `sudo apt-get -y install python-pip python git` or `sudo yum -y install python-pip python git`
        * `sudo pip install boto3`
        * `git clone https://github.com/awslabs/aws-securityhub-multiaccount-scripts.git`
        * `cd aws-securityhub-multiaccount-scripts/multiaccount-product-disablement`

### 2. Create CSV File

Create a CSV file with your account information. Each line should contain an account ID:

**Format:**
```
123456789012
234567890123
345678901234
```

### 3. Execute Script

```
usage: productdisablement.py [-h] --assume_role_name ASSUME_ROLE_NAME
                              --regions-to-disable REGIONS_TO_DISABLE
                              --products PRODUCTS [--dry-run]
                              [input_file]

Disable Security Hub CSPM product integrations across multiple AWS accounts

positional arguments:
  input_file            Optional: Path to CSV file containing account IDs (one per
                        line). If not provided, uses all Security Hub member accounts

required arguments:
  --assume_role_name ASSUME_ROLE_NAME
                        Role Name to assume in each account
  --regions-to-disable REGIONS_TO_DISABLE
                        Comma separated list of regions to disable products,
                        or 'ALL' for all available regions (format: us-east-1, eu-west-1, etc.)
  --products PRODUCTS   Comma separated list of product identifiers to disable
                        (e.g., 'aws/guardduty,aws/macie' or product ARNs)

optional arguments:
  -h, --help            show this help message and exit
  --dry-run             Preview changes without actually disabling products.
                        Shows what would be disabled.
```

## Usage Examples

### Dry-Run Mode (Preview Changes)

**Recommended:** Always run with `--dry-run` first to preview what will be changed before executing:

```bash
# Preview disabling GuardDuty across all accounts in all regions (NO CHANGES MADE)
python productdisablement.py \
    --assume_role_name SecurityHubRole \
    --regions-to-disable ALL \
    --products "aws/guardduty" \
    --dry-run
```

```bash
# Preview disabling multiple products in specific regions (NO CHANGES MADE)
python productdisablement.py \
    --assume_role_name SecurityHubRole \
    --regions-to-disable us-east-1,us-west-2 \
    --products "aws/guardduty,aws/macie" \
    --dry-run
```

Once you've reviewed the dry-run output and confirmed the changes, remove the `--dry-run` flag to execute.

### Using Auto-Discovery (No CSV File)

When running from the Security Hub CSPM Delegated Administrator account, the script automatically discovers all Security Hub CSPM member accounts in your AWS Organization:

```bash
# Disable GuardDuty across ALL Security Hub member accounts in all regions
python productdisablement.py \
    --assume_role_name SecurityHubRole \
    --regions-to-disable ALL \
    --products "aws/guardduty"
```

```bash
# Disable multiple products across ALL Security Hub member accounts in specific regions
python productdisablement.py \
    --assume_role_name SecurityHubRole \
    --regions-to-disable us-east-1,us-west-2,eu-west-1 \
    --products "aws/guardduty,aws/macie,aws/inspector"
```

### Using CSV File

When providing a CSV file, the script processes the accounts listed in the CSV:

```bash
# Disable GuardDuty for specific accounts (intersection of CSV and members)
python productdisablement.py accounts.csv \
    --assume_role_name SecurityHubRole \
    --regions-to-disable ALL \
    --products "aws/guardduty"
```

```bash
# Disable multiple products in specific accounts and regions
python productdisablement.py accounts.csv \
    --assume_role_name SecurityHubRole \
    --regions-to-disable us-east-1,us-west-2,eu-west-1 \
    --products "aws/guardduty,aws/macie,aws/inspector"
```

```bash
# Disable Access Analyzer and Firewall Manager in specific accounts, us-east-1 only
python productdisablement.py accounts.csv \
    --assume_role_name SecurityHubRole \
    --regions-to-disable us-east-1 \
    --products "aws/access-analyzer,aws/firewall-manager"
```

## Product Identifiers

You can specify products using either format:
- **Short name format**: `aws/guardduty`, `aws/macie`, `aws/inspector`
- **Full ARN format**: `arn:aws:securityhub:us-east-1:123456789012:product-subscription/aws/guardduty`

### Common AWS Product Identifiers

| Product Identifier | Service |
|-------------------|---------|
| `aws/guardduty` | Amazon GuardDuty |
| `aws/macie` | Amazon Macie |
| `aws/inspector` | Amazon Inspector |
| `aws/access-analyzer` | IAM Access Analyzer |
| `aws/firewall-manager` | AWS Firewall Manager |
| `aws/health` | AWS Health |
| `aws/systems-manager-patch-manager` | Systems Manager Patch Manager |


## Important Notes

* **Products not currently enabled are skipped** - The script will not error if a specified product is not enabled in an account/region
* **Idempotent operation** - Safe to run multiple times; products already disabled will not cause errors
* **Per-account, per-region processing** - Each account's enabled products are queried independently; the script only disables products that match the specified identifiers
* **Continues on failure** - If one account fails, the script continues processing remaining accounts
* **Works with any account type** - Standalone accounts, organization member accounts, or delegated administrator accounts
