from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class PerformanceQueried:
	def __init__(self, file_beh: dict):
		file_beh['performanceQueried']['table']
		self.item_list = {}
		for each_items in file_beh['performanceQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = convert_to_int(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['15'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(8, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class TicksQueried:
	def __init__(self, file_beh: dict):
		file_beh['ticksQueried']['table']
		self.item_list = {}
		for each_items in file_beh['ticksQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = convert_to_int(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['15'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(8, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class TimeQueried:
	def __init__(self, file_beh: dict):
		file_beh['timeQueried']['table']
		self.item_list = {}
		for each_items in file_beh['timeQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = convert_to_int(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['15'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(8, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class TimerSet:
	def __init__(self, file_beh: dict):
		file_beh['timerSet']['table']
		self.item_list = {}
		for each_items in file_beh['timerSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = convert_to_int(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['15'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(8, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class UserTimerSet:
	def __init__(self, file_beh: dict):
		file_beh['userTimerSet']['table']
		self.item_list = {}
		for each_items in file_beh['userTimerSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = convert_to_int(list_field[0])

			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['15'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(8, '0'),
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return