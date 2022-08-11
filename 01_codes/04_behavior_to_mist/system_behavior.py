from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class CommandLineQueried:
	def __init__(self, file_beh: dict):
		file_beh['commandLineQueried']['table']
		self.item_list = {}
		for each_items in file_beh['commandLineQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['14'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ComputerNameQueried:
	def __init__(self, file_beh: dict):
		file_beh['computerNameQueried']['table']
		self.item_list = {}
		for each_items in file_beh['computerNameQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			count = convert_to_int(list_field[0])
			source_addr = convert_to_int(list_field[1])
			symbol = custom_hash(list_field[2])

			item_str = ' '.join(['14'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class CpuIDQueried:
	def __init__(self, file_beh: dict):
		file_beh['cpuIDQueried']['table']
		self.item_list = {}
		for each_items in file_beh['cpuIDQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			function_id = custom_hash(list_field[0])
			sub_function_id = custom_hash(list_field[1])
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(function_id)[2:].rjust(16, '0'), 
				hex(sub_function_id)[2:].rjust(16, '0'), 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class HardErrorRaised:
	def __init__(self, file_beh: dict):
		file_beh['hardErrorRaised']['table']
		self.item_list = {}
		for each_items in file_beh['hardErrorRaised']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class KeyboardLayoutListQueried:
	def __init__(self, file_beh: dict):
		file_beh['keyboardLayoutListQueried']['table']
		self.item_list = {}
		for each_items in file_beh['keyboardLayoutListQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			completion = 0x1 if 'success' in list_field[0] else 0x0
			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['13'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class KeyboardLayoutQueried:
	def __init__(self, file_beh: dict):
		file_beh['keyboardLayoutQueried']['table']
		self.item_list = {}
		for each_items in file_beh['keyboardLayoutQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			completion = 0x1 if 'success' in list_field[0] else 0x0
			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['13'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class LanguageOrLocaleQueried:
	def __init__(self, file_beh: dict):
		file_beh['languageOrLocaleQueried']['table']
		self.item_list = {}
		for each_items in file_beh['languageOrLocaleQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			completion = 0x1 if 'success' in list_field[0] else 0x0
			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['13'.rjust(2, '0'), '7'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ServiceCreated:
	def __init__(self, file_beh: dict):
		file_beh['serviceCreated']['table']
		self.item_list = {}
		for each_items in file_beh['serviceCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			service_name = custom_hash(list_field[0])
			display_name = custom_hash(list_field[1])
			service_type = custom_hash(list_field[2])
			startup = custom_hash(list_field[3])
			old_file = Path(list_field[4])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['13'.rjust(2, '0'), '8'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(service_name)[2:].rjust(16, '0'), 
				hex(display_name)[2:].rjust(16, '0'), 
				hex(service_type)[2:].rjust(16, '0'), 
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ServiceDeleted:
	def __init__(self, file_beh: dict):
		file_beh['serviceDeleted']['table']
		self.item_list = {}
		for each_items in file_beh['serviceDeleted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '9'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ServiceOpened:
	def __init__(self, file_beh: dict):
		file_beh['serviceOpened']['table']
		self.item_list = {}
		for each_items in file_beh['serviceOpened']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '10'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ServiceStarted:
	def __init__(self, file_beh: dict):
		file_beh['serviceStarted']['table']
		self.item_list = {}
		for each_items in file_beh['serviceStarted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '11'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SystemParameter:
	def __init__(self, file_beh: dict):
		file_beh['systemParameter']['table']
		self.item_list = {}
		for each_items in file_beh['systemParameter']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])
			para = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['14'.rjust(2, '0'), '12'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SystemPowerStateSet:
	def __init__(self, file_beh: dict):
		file_beh['systemPowerStateSet']['table']
		self.item_list = {}
		for each_items in file_beh['systemPowerStateSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])
			para = custom_hash(list_field[1])
			flag = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['14'.rjust(2, '0'), '13'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(flag)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SystemQueried:
	def __init__(self, file_beh: dict):
		file_beh['systemQueried']['table']
		self.item_list = {}
		for each_items in file_beh['systemQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '14'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SystemSet:
	def __init__(self, file_beh: dict):
		file_beh['systemSet']['table']
		self.item_list = {}
		for each_items in file_beh['systemSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])
			para = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['14'.rjust(2, '0'), '15'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SystemShutdown:
	def __init__(self, file_beh: dict):
		file_beh['systemShutdown']['table']
		self.item_list = {}
		for each_items in file_beh['systemShutdown']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['14'.rjust(2, '0'), '16'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class UserNameQueried:
	def __init__(self, file_beh: dict):
		file_beh['userNameQueried']['table']
		self.item_list = {}
		for each_items in file_beh['userNameQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			count = convert_to_int(list_field[0])
			source_addr = convert_to_int(list_field[1])
			symbol = custom_hash(list_field[2])

			item_str = ' '.join(['14'.rjust(2, '0'), '17'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class VersionQueried:
	def __init__(self, file_beh: dict):
		file_beh['versionQueried']['table']
		self.item_list = {}
		for each_items in file_beh['versionQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			count = convert_to_int(list_field[0])
			source_addr = convert_to_int(list_field[1])
			symbol = custom_hash(list_field[2])

			item_str = ' '.join(['14'.rjust(2, '0'), '18'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return