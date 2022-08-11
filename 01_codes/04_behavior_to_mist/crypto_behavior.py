from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class CertificateCreated:
	def __init__(self, file_beh: dict):
		file_beh['certificateCreated']['table']
		self.item_list = {}
		for each_items in file_beh['certificateCreated']['items']:
			list_field = each_items['fields']
			item_str = ''

			cert_data = custom_hash(list_field[0])
			encoding = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['10'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(encoding)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class DataDecrypted:
	def __init__(self, file_beh: dict):
		file_beh['dataDecrypted']['table']
		self.item_list = {}
		for each_items in file_beh['dataDecrypted']['items']:
			list_field = each_items['fields']
			item_str = ''

			cert_data = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['10'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class DataEncrypted:
	def __init__(self, file_beh: dict):
		file_beh['dataEncrypted']['table']
		self.item_list = {}
		for each_items in file_beh['dataEncrypted']['items']:
			list_field = each_items['fields']
			item_str = ''

			cert_data = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['10'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class GenKey:
	def __init__(self, file_beh: dict):
		file_beh['genKey']['table']
		self.item_list = {}
		for each_items in file_beh['genKey']['items']:
			list_field = each_items['fields']
			item_str = ''

			Algorithm = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['10'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(Algorithm)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class KeyImported:
	def __init__(self, file_beh: dict):
		file_beh['keyImported']['table']
		self.item_list = {}
		for each_items in file_beh['keyImported']['items']:
			list_field = each_items['fields']
			item_str = ''

			cert_data = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['10'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class KeyExported:
	def __init__(self, file_beh: dict):
		file_beh['keyExported']['table']
		self.item_list = {}
		for each_items in file_beh['keyExported']['items']:
			list_field = each_items['fields']
			item_str = ''

			cert_data = custom_hash(list_field[0])
			blob_type = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['10'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return