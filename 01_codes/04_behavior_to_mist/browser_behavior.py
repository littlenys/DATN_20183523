from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class Cdocumentwrite:
	def __init__(self, file_beh: dict):
		file_beh['cdocumentwrite']['table']
		self.item_list = {}
		for each_items in file_beh['cdocumentwrite']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			html_code = custom_hash(list_field[0])
			
			item_str = ' '.join(['8'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(html_code)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InetConnect:
	def __init__(self, file_beh: dict):
		file_beh['inetConnect']['table']
		self.item_list = {}
		for each_items in file_beh['inetConnect']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			server_name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['8'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InetOpenRequest:
	def __init__(self, file_beh: dict):
		file_beh['inetOpenRequest']['table']
		self.item_list = {}
		for each_items in file_beh['inetOpenRequest']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			server_name = custom_hash(list_field[0])
			verb = custom_hash(list_field[1])
			para = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['8'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(server_name)[2:].rjust(16, '0'),
				hex(verb)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InetReadFile:
	def __init__(self, file_beh: dict):
		file_beh['inetReadFile']['table']
		self.item_list = {}
		for each_items in file_beh['inetReadFile']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			server_name = custom_hash(list_field[0])
			verb = custom_hash(list_field[1])
			para = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['8'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(server_name)[2:].rjust(16, '0'),
				hex(verb)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InetWriteFile:
	def __init__(self, file_beh: dict):
		file_beh['inetWriteFile']['table']
		self.item_list = {}
		for each_items in file_beh['inetWriteFile']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			server_name = custom_hash(list_field[0])
			verb = custom_hash(list_field[1])
			para = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['8'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(server_name)[2:].rjust(16, '0'),
				hex(verb)[2:].rjust(16, '0'),
				hex(para)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class Jsscriptcompile:
	def __init__(self, file_beh: dict):
		file_beh['jsscriptcompile']['table']
		self.item_list = {}
		for each_items in file_beh['jsscriptcompile']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			html_code = custom_hash(list_field[0])
			
			item_str = ' '.join(['8'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(html_code)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return