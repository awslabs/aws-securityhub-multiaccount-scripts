import utils

region = 'ap-northeast-1'
standard_resource = 'arn:aws:securityhub:::ruleset/pci-dss/v/3.2.1'

print(utils.get_standard_arn_for_region_and_resource(region, standard_resource))
