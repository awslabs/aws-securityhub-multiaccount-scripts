CIS_STANDARD_RESOURCE = 'ruleset/cis-aws-foundations-benchmark/v/1.2.0'
CIS_STANDARD_ARN = 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0'
"arn:aws:securityhub:us-west-2::standards/pci-dss/v/3.2.1"
def get_standard_arn_for_region_and_resource(region, standard_resource):
    if standard_resource == CIS_STANDARD_ARN or standard_resource == CIS_STANDARD_RESOURCE:
        return CIS_STANDARD_ARN
    else:
        return 'arn:{partition}:securityhub:{region}::{resource}'.format(partition='aws', region=region, resource=standard_resource)
