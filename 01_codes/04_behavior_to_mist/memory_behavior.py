from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class MemAccess:
	def __init__(self, file_beh: dict):
		file_beh['memAccess']['table']
		self.item_list = {}
		for each_items in file_beh['memAccess']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			struct = custom_hash(list_field[0])
			eip = convert_to_int(list_field[1])
			address = convert_to_int(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['5'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(struct)[2:].rjust(16, '0'), 
				hex(eip)[2:].rjust(16, '0'), 
				hex(address)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MemAlloc:
	def __init__(self, file_beh: dict):
		file_beh['memAlloc']['table']
		self.item_list = {}
		for each_items in file_beh['memAlloc']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])
			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			base = convert_to_int(list_field[2])
			length = convert_to_int(list_field[3])

			type_mem = 0
			if 'reserve' in list_field[4]:
				type_mem |= 1

			if 'commit' in list_field[4]:
				type_mem |= (1 >> 1)

			if 'write' in list_field[4]:
				type_mem |= (1 >> 2)

			if 'top down' in list_field[4]:
				type_mem |= (1 >> 3)

			protection = 0
			if 'read' in list_field[5]:
				protection |= 1

			if 'write' in list_field[5]:
				protection |= (1 >> 1)

			if 'execution' in list_field[5]:
				protection |= (1 >> 2)

			completion = 0x1 if 'success' in list_field[6] else 0x0
			count = convert_to_int(list_field[7])
			source_addr = convert_to_int(list_field[8])
			symbol = custom_hash(list_field[9])

			item_str = ' '.join(['5'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(PID)[2:].rjust(8, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(type_mem)[2:].rjust(3, '0'),
				hex(protection)[2:].rjust(3, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MemProtect:
	def __init__(self, file_beh: dict):
		file_beh['memProtect']['table']
		self.item_list = {}
		for each_items in file_beh['memProtect']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])
			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			base = convert_to_int(list_field[2])
			length = convert_to_int(list_field[3])

			protection = 0
			if 'read' in list_field[4]:
				protection |= 1

			if 'write' in list_field[4]:
				protection |= (1 >> 1)

			if 'execution' in list_field[4]:
				protection |= (1 >> 2)

			new_protection = 0
			if 'read' in list_field[5]:
				new_protection |= 1

			if 'write' in list_field[5]:
				new_protection |= (1 >> 1)

			if 'execution' in list_field[5]:
				new_protection |= (1 >> 2)

			completion = 0x1 if 'success' in list_field[6] else 0x0
			count = convert_to_int(list_field[7])
			source_addr = convert_to_int(list_field[8])
			symbol = custom_hash(list_field[9])

			item_str = ' '.join(
				['5'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(PID)[2:].rjust(8, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(protection)[2:].rjust(3, '0'),
				hex(new_protection)[2:].rjust(3, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MemRead:
	def __init__(self, file_beh: dict):
		file_beh['memRead']['table']
		self.item_list = {}
		for each_items in file_beh['memRead']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])
			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			base = convert_to_int(list_field[2])
			length = convert_to_int(list_field[3])

			value = custom_hash(list_field[4])

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(
				['5'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(PID)[2:].rjust(8, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(value)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MemWritten:
	def __init__(self, file_beh: dict):
		file_beh['memWritten']['table']
		self.item_list = {}
		for each_items in file_beh['memWritten']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])
			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			base = convert_to_int(list_field[2])
			length = convert_to_int(list_field[3])

			value = custom_hash(list_field[4])

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(
				['5'.rjust(2, '0'), ''.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(PID)[2:].rjust(8, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(value)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return