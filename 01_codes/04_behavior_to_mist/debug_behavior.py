from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class DebugSet:
	def __init__(self, file_beh: dict):
		file_beh['debugSet']['table']
		self.item_list = {}
		for each_items in file_beh['debugSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			cert_data = custom_hash(list_field[0])
			encoding = custom_hash(list_field[1])
			output_data = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['11'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(cert_data)[2:].rjust(16, '0'),
				hex(encoding)[2:].rjust(16, '0'),
				hex(output_data)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return