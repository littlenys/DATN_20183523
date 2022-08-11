from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class ThreadAPCQueued:
	def __init__(self, file_beh: dict):
		file_beh['threadAPCQueued']['table']
		self.item_list = {}
		for each_items in file_beh['threadAPCQueued']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])
			Injected = 0x1 if 'true' in list_field[2] else 0x0

			old_file = Path(list_field[3])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))



			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['7'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(PID)[2:].rjust(8, '0'),
				hex(Injected)[2:].rjust(2, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadCreated:
	def __init__(self, file_beh: dict):
		file_beh['threadCreated']['table']
		self.item_list = {}
		for each_items in file_beh['threadCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])
			EIP = convert_to_int(list_field[2])
			EAX = convert_to_int(list_field[3])

			old_file = Path(list_field[4])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))



			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['7'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(PID)[2:].rjust(8, '0'),
				hex(EIP)[2:].rjust(16, '0'),
				hex(EAX)[2:].rjust(16, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadDelayed:
	def __init__(self, file_beh: dict):
		file_beh['threadDelayed']['table']
		self.item_list = {}
		for each_items in file_beh['threadDelayed']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			Delay = convert_to_int(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['7'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(Delay)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadGot:
	def __init__(self, file_beh: dict):
		file_beh['threadGot']['table']
		self.item_list = {}
		for each_items in file_beh['threadGot']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])
			DR0 = convert_to_int(list_field[2])
			DR1 = convert_to_int(list_field[3])
			DR2 = convert_to_int(list_field[4])
			DR3 = convert_to_int(list_field[5])
			DR7 = convert_to_int(list_field[6])
			EFLAGS = convert_to_int(list_field[7])
			EIP = convert_to_int(list_field[8])

			completion = 0x1 if 'success' in list_field[9] else 0x0
			count = convert_to_int(list_field[10])
			source_addr = convert_to_int(list_field[11])
			symbol = custom_hash(list_field[12])

			item_str = ' '.join(['7'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(16, '0'),
				hex(PID)[2:].rjust(16, '0'),
				hex(DR0)[2:].rjust(16, '0'),
				hex(DR1)[2:].rjust(16, '0'),
				hex(DR2)[2:].rjust(16, '0'),
				hex(DR3)[2:].rjust(16, '0'),
				hex(DR7)[2:].rjust(16, '0'),
				hex(EFLAGS)[2:].rjust(16, '0'),
				hex(EIP)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadInformationSet:
	def __init__(self, file_beh: dict):
		file_beh['threadInformationSet']['table']
		self.item_list = {}
		for each_items in file_beh['threadInformationSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			info_class = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['7'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(info_class)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadResumed:
	def __init__(self, file_beh: dict):
		file_beh['threadResumed']['table']
		self.item_list = {}
		for each_items in file_beh['threadResumed']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])

			old_file = Path(list_field[2])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['7'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(PID)[2:].rjust(8, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadSet:
	def __init__(self, file_beh: dict):
		file_beh['threadSet']['table']
		self.item_list = {}
		for each_items in file_beh['threadSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])
			DR0 = convert_to_int(list_field[2])
			DR1 = convert_to_int(list_field[3])
			DR2 = convert_to_int(list_field[4])
			DR3 = convert_to_int(list_field[5])
			DR7 = convert_to_int(list_field[6])
			EFLAGS = convert_to_int(list_field[7])
			EIP = convert_to_int(list_field[8])

			completion = 0x1 if 'success' in list_field[9] else 0x0
			count = convert_to_int(list_field[10])
			source_addr = convert_to_int(list_field[11])
			symbol = custom_hash(list_field[12])

			item_str = ' '.join(['7'.rjust(2, '0'), '7'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(16, '0'),
				hex(PID)[2:].rjust(16, '0'),
				hex(DR0)[2:].rjust(16, '0'),
				hex(DR1)[2:].rjust(16, '0'),
				hex(DR2)[2:].rjust(16, '0'),
				hex(DR3)[2:].rjust(16, '0'),
				hex(DR7)[2:].rjust(16, '0'),
				hex(EFLAGS)[2:].rjust(16, '0'),
				hex(EIP)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class threadTerminated:
	def __init__(self, file_beh: dict):
		file_beh['threadTerminated']['table']
		self.item_list = {}
		for each_items in file_beh['threadTerminated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['7'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(PID)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ThreadSuspended:
	def __init__(self, file_beh: dict):
		file_beh['threadSuspended']['table']
		self.item_list = {}
		for each_items in file_beh['threadSuspended']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			TID = convert_to_int(list_field[0])
			PID = convert_to_int(list_field[1])
			old_file = Path(list_field[2])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))


			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['7'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(TID)[2:].rjust(8, '0'),
				hex(PID)[2:].rjust(8, '0'),
				hex(EIP)[2:].rjust(16, '0'),
				hex(EAX)[2:].rjust(16, '0'),
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return