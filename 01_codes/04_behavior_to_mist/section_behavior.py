from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class ModuleHandleQueried:
	def __init__(self, file_beh: dict):
		file_beh['moduleHandleQueried']['table']
		self.item_list = {}
		for each_items in file_beh['moduleHandleQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			string1 = custom_hash(list_field[0])
			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['19'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(string1)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ProcAddressQueried:
	def __init__(self, file_beh: dict):
		file_beh['procAddressQueried']['table']
		self.item_list = {}
		for each_items in file_beh['procAddressQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			string1 = custom_hash(list_field[0])
			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['19'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(string1)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ResourceQueried:
	def __init__(self, file_beh: dict):
		file_beh['resourceQueried']['table']
		self.item_list = {}
		for each_items in file_beh['resourceQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])
			Type = custom_hash(list_field[1])
			module_name = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['19'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'), 
				hex(Type)[2:].rjust(16, '0'), 
				hex(module_name)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class SectionLoadedW:
	def __init__(self, file_beh: dict):
		file_beh['sectionLoadedW']['table']
		self.item_list = {}
		for each_items in file_beh['sectionLoadedW']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			access = 0
			if 'query' in list_field[1]:
				access |= 1
			if 'write' in list_field[1]:
				access |= (1 >> 1)
			if 'read' in list_field[1]:
				access |= (1 >> 2)
			if 'execute' in list_field[1]:
				access |= (1 >> 3)

			type_section = custom_hash(list_field[2])
			base = convert_to_int(list_field[3])
			size = convert_to_int(list_field[4])
			mapped_to_pid = custom_hash(list_field[5])
			protection = 0
			if 'read' in list_field[6]:
				protection |= 1
			if 'write' in list_field[6]:
				protection |= (1 >> 1)

			completion = 0x1 if 'success' in list_field[7] else 0x0
			count = convert_to_int(list_field[8])

			item_str = ' '.join(['19'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:],
				hex(old_file_parent)[2:], 
				hex(access)[2:], 
				hex(type_section)[2:], 
				hex(base)[2:], 
				hex(size)[2:], 
				hex(mapped_to_pid)[2:], 
				hex(protection)[2:], 
				hex(completion)[2:], 
				hex(count)[2:].rjust(4, '0')])
			self.item_list[bID] = item_str
		return

class SectionLoadedP:
	def __init__(self, file_beh: dict):
		file_beh['sectionLoadedP']['table']
		self.item_list = {}
		for each_items in file_beh['sectionLoadedP']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			access = 0
			if 'query' in list_field[1]:
				access |= 1
			if 'write' in list_field[1]:
				access |= (1 >> 1)
			if 'read' in list_field[1]:
				access |= (1 >> 2)
			if 'execute' in list_field[1]:
				access |= (1 >> 3)

			type_section = custom_hash(list_field[2])
			base = convert_to_int(list_field[3])
			size = convert_to_int(list_field[4])
			mapped_to_pid = custom_hash(list_field[5])
			protection = 0
			if 'read' in list_field[6]:
				protection |= 1
			if 'write' in list_field[6]:
				protection |= (1 >> 1)

			completion = 0x1 if 'success' in list_field[7] else 0x0
			count = convert_to_int(list_field[8])

			item_str = ' '.join(['19'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:],
				hex(old_file_parent)[2:], 
				hex(access)[2:], 
				hex(type_section)[2:], 
				hex(base)[2:], 
				hex(size)[2:], 
				hex(mapped_to_pid)[2:], 
				hex(protection)[2:], 
				hex(completion)[2:], 
				hex(count)[2:].rjust(4, '0')])
			self.item_list[bID] = item_str
		return