from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class Adapterinfoquery:
	def __init__(self, file_beh: dict):
		file_beh['adapterinfoquery']['table']
		self.item_list = {}
		for each_items in file_beh['adapterinfoquery']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			completion = 0x1 if 'success' in list_field[0] else 0x0
			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['21', '1', '|', 
				hex(symbol)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Addrinfoquery:
	def __init__(self, file_beh: dict):
		file_beh['addrinfoquery']['table']
		self.item_list = {}
		for each_items in file_beh['addrinfoquery']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			node_name = custom_hash(list_field[0])
			service_name = custom_hash(list_field[1])
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['21', '2', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(service_name)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Httpopenrequest:
	def __init__(self, file_beh: dict):
		file_beh['httpopenrequest']['table']
		self.item_list = {}
		for each_items in file_beh['httpopenrequest']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			node_name = custom_hash(list_field[0])
			service_name = custom_hash(list_field[1])
			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['21', '3', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(service_name)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Internetconnect:
	def __init__(self, file_beh: dict):
		file_beh['internetconnect']['table']
		self.item_list = {}
		for each_items in file_beh['internetconnect']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			node_name = custom_hash(list_field[0])
			port = convert_to_int(list_field[1])
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['21', '4', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(service_name)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Networkconnect:
	def __init__(self, file_beh: dict):
		file_beh['networkconnect']['table']
		self.item_list = {}
		for each_items in file_beh['networkconnect']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			node_name = custom_hash(list_field[0])
			port = convert_to_int(list_field[1])
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['21', '5', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(port)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Networkbind:
	def __init__(self, file_beh: dict):
		file_beh['networkbind']['table']
		self.item_list = {}
		for each_items in file_beh['networkbind']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			node_name = custom_hash(list_field[0])
			port = convert_to_int(list_field[1])
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['21', '6', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(service_name)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Networkresourceconnected:
	def __init__(self, file_beh: dict):
		file_beh['networkresourceconnected']['table']
		self.item_list = {}
		for each_items in file_beh['networkresourceconnected']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			local_name = custom_hash(list_field[0])
			remote_name = custom_hash(list_field[1])
			provider = custom_hash(list_field[2])
			password = custom_hash(list_field[3])
			username = custom_hash(list_Field[4])
			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['21', '7', '|', 
				hex(symbol)[2:], 
				hex(node_name)[2:],
				hex(service_name)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class Tcporudptablequeried:
	def __init__(self, file_beh: dict):
		file_beh['tcporudptablequeried']['table']
		self.item_list = {}
		for each_items in file_beh['tcporudptablequeried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			completion = 0x1 if 'success' in list_field[0] else 0x0
			count = convert_to_int(list_field[1])
			source_addr = convert_to_int(list_field[2])
			symbol = custom_hash(list_field[3])

			item_str = ' '.join(['21', '8', '|', 
				hex(symbol)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return