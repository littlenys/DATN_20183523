from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path


class KeyCreated:
	def __init__(self, file_beh: dict):
		file_beh['keyCreated']['table']
		self.item_list = {}
		for each_items in file_beh['keyCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['2', '1', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyDeleted:
	def __init__(self, file_beh: dict):
		file_beh['keyDeleted']['table']
		self.item_list = {}
		for each_items in file_beh['keyDeleted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['2', '2', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyEnumerated:
	def __init__(self, file_beh: dict):
		file_beh['keyEnumerated']['table']
		self.item_list = {}
		for each_items in file_beh['keyEnumerated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			key_filter = convert_to_int(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['2', '3', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(key_filter)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyMonitored:
	def __init__(self, file_beh: dict):
		file_beh['keyMonitored']['table']
		self.item_list = {}
		for each_items in file_beh['keyMonitored']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			key_filter = 0
			if 'attributes' in list_field[1]:
				key_filter |= 1

			if 'last set' in list_field[1]:
				key_filter |= (1 << 1)

			if 'security' in list_field[1]:
				key_filter |= (1 << 2)

			if 'name' in list_field[1]:
				key_filter |= (1 << 3)

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['2', '4', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(key_filter)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyOpened:
	def __init__(self, file_beh: dict):
		file_beh['keyOpened']['table']
		self.item_list = {}
		for each_items in file_beh['keyOpened']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['2', '5', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyValueCreated:
	def __init__(self, file_beh: dict):
		file_beh['keyValueCreated']['table']
		self.item_list = {}
		for each_items in file_beh['keyValueCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			name = custom_hash(list_field[1])
			type_data = custom_hash(list_field[2])
			data = custom_hash(list_field[3])

			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['2', '6', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(name)[2:], 
				hex(type_data)[2:], 
				hex(data)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyValueDeleted:
	def __init__(self, file_beh: dict):
		file_beh['keyValueDeleted']['table']
		self.item_list = {}
		for each_items in file_beh['keyValueDeleted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			name = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['2', '7', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyValueEnumerated:
	def __init__(self, file_beh: dict):
		file_beh['keyValueEnumerated']['table']
		self.item_list = {}
		for each_items in file_beh['keyValueEnumerated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			key_filter = convert_to_int(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['2', '8', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(key_filter)[2:].rjust(6, 0),
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyValueModified:
	def __init__(self, file_beh: dict):
		file_beh['keyValueModified']['table']
		self.item_list = {}
		for each_items in file_beh['keyValueModified']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			name = custom_hash(list_field[1])
			type_data = custom_hash(list_field[2])
			data = custom_hash(list_field[3])
			new_data = custom_hash(list_field[4])

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['2', '9', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(name)[2:], 
				hex(type_data)[2:], 
				hex(data)[2:], 
				hex(new_data)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class KeyValueQueried:
	def __init__(self, file_beh: dict):
		file_beh['keyValueQueried']['table']
		self.item_list = {}
		for each_items in file_beh['keyValueQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			name = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['2', '10', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return