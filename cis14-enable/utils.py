#format is CIS 1.2 control ID = CIS 1.4 control ID

CIS_control_map = {
	'CIS.1.1':'CIS.1.7',
	'CIS.2.1':'CIS.3.1',
	'CIS.2.7':'CIS.3.7',
	'CIS.2.2':'CIS.3.2',
	'CIS.2.4':'CIS.3.4',
	'CIS.3.4':'CIS.4.4',
	'CIS.3.5':'CIS.4.5',
	'CIS.3.6':'CIS.4.6',
	'CIS.3.7':'CIS.4.7',
	'CIS.3.8':'CIS.4.8',
	'CIS.3.9':'CIS.4.9',
	'CIS.3.11':'CIS.4.11',
	'CIS.3.12':'CIS.4.12',
	'CIS.3.13':'CIS.4.13',
	'CIS.3.14':'CIS.4.14',
	'CIS.2.5':'CIS.3.5',
	'CIS.4.3':'CIS.5.3',
	'CIS.2.9':'CIS.3.9',
	'CIS.1.22':'CIS.1.16',
	'CIS.1.4':'CIS.1.14',
	'CIS.1.12':'CIS.1.4',
	'CIS.1.14':'CIS.1.6',
	'CIS.1.13':'CIS.1.5',
	'CIS.1.9':'CIS.1.8',
	'CIS.1.10':'CIS.1.9',
	'CIS.1.20':'CIS.1.17',
	'CIS.2.8':'CIS.3.8',
	'CIS.1.3':'CIS.1.12',
	'CIS.2.3':'CIS.3.3'				
	}

def get_control_map(old_control):
	try:
		new_control = CIS_control_map[old_control]
		return new_control
	except KeyError:
		return


