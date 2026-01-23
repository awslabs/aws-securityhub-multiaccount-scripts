## AWS Security Hub multi-account scripts

*****
> **Note:**<br>
> Security Hub now supports central configuration for security standards and controls across accounts. 
>
> Security Hub's central configration feature addresses many of the scenarios that are covered by the scripts in this repository, reducing or eliminating the need to run these scripts.  Please refer to the [Security Hub central configuration documentation](https://docs.aws.amazon.com/securityhub/latest/userguide/central-configuration-intro.html) first before going forward with using these scripts.
*****



This repository contains scripts and guidance for enabling and configuring Security Hub and Security Hub features across multiple accounts.  

The five scenarios addressed by this repository are:
* [Multi-account enablement scripts](multiaccount-enable) - scripts focused on enabling or disabling Security Hub across many accounts.  Applicable for accounts that are not managed by a [delegated administrator](https://docs.aws.amazon.com/securityhub/latest/userguide/designate-orgs-admin-account.html) account. 

* [Multi-account CIS 1.4 enable scripts](cis14-enable) - scripts focused on enabling the Center for Internet Security AWS Foundational Best Practices v1.4 security standard across many accounts.  

* [Multi-account NIST 800-53 enable scripts](nist800-53-enable) - scripts focused on enabling or disabling the NIST 800-53 security standard across many accounts.
 
* [Multi-region automation rules deployment](automation-rules) - scripts focused on deploying automation rules across multiple regions in an account.

* [Multi-account product disablement scripts](multiaccount-product-disablement) - scripts focused on disabling Security Hub product integrations across multiple accounts, with support for dry-run mode to preview changes before execution.
