from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class ProcessCreated:
	def __init__(self, file_beh: dict):
		file_beh['processCreated']['table']
		self.item_list = {}
		for each_items in file_beh['processCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			cmdline = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['3'.rjust(2, '0'), '1'.rjust(2, '0'), '|', hex(PID)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0'), hex(cmdline)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str

class ProcessQueried:
	def __init__(self, file_beh: dict):
		file_beh['processQueried']['table']
		self.item_list = {}
		for each_items in file_beh['processQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			cmdline = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['3'.rjust(2, '0'), '2'.rjust(2, '0'), '|', hex(PID)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0'), hex(cmdline)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str

class ProcessSet:
	def __init__(self, file_beh: dict):
		file_beh['processSet']['table']
		self.item_list = {}
		for each_items in file_beh['processSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			cmdline = custom_hash(list_field[2])
			process_info = custom_hash(list_field[3])

			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['3'.rjust(2, '0'), '3'.rjust(2, '0'), '|', hex(PID)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(process_info)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0'), hex(cmdline)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str

class ProcessSuspended:
	def __init__(self, file_beh: dict):
		file_beh['processSuspended']['table']
		self.item_list = {}
		for each_items in file_beh['processSuspended']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			cmdline = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['3'.rjust(2, '0'), '4'.rjust(2, '0'), '|', hex(PID)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0'), hex(cmdline)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str

class ProcessTerminated:
	def __init__(self, file_beh: dict):
		file_beh['processTerminated']['table']
		self.item_list = {}
		for each_items in file_beh['processTerminated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			PID = convert_to_int(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['3'.rjust(2, '0'), '5'.rjust(2, '0'), '|', hex(PID)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str

class ShellExecuted:
	def __init__(self, file_beh: dict):
		file_beh['shellExecuted']['table']
		self.item_list = {}
		for each_items in file_beh['shellExecuted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			Operation = custom_hash(list_field[0])

			old_file = Path(list_field[1])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			Parameter = custom_hash(list_field[2])
			Directory = custom_hash(list_field[3])
			show_command = custom_hash(list_field[4])

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['3'.rjust(2, '0'), '6'.rjust(2, '0'), '|', hex(Operation)[2:].rjust(16, '0'), hex(Parameter)[2:].rjust(16, '0'), hex(Directory)[2:].rjust(16, '0'), hex(show_command)[2:].rjust(16, '0'), hex(symbol)[2:].rjust(16, '0'), hex(old_file_name)[2:].rjust(16, '0'), hex(old_file_hash)[2:].rjust(16, '0'), hex(old_file_parent)[2:].rjust(16, '0'), hex(completion)[2:].rjust(2, '0'), hex(count)[2:].rjust(4, '0'), hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str