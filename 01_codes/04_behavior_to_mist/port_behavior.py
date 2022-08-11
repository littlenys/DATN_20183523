from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class ConsoleWritten:
	def __init__(self, file_beh: dict):
		file_beh['consoleWritten']['table']
		self.item_list = {}
		self.item_list = {}
		for each_items in file_beh['consoleWritten']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			string1 = custom_hash(list_field[0])
			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['20'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(string1)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class PortRequestWaitReplay:
	def __init__(self, file_beh: dict):
		file_beh['portRequestWaitReplay']['table']
		self.item_list = {}
		self.item_list = {}
		for each_items in file_beh['portRequestWaitReplay']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			string1 = custom_hash(list_field[0])
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['20'.rjust(2, '0'), ''.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(string1)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return