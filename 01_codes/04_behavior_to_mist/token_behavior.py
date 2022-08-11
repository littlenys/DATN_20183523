from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class AdjustToken:
	def __init__(self, file_beh: dict):
		file_beh['adjustToken']['table']
		self.item_list = {}
		for each_items in file_beh['adjustToken']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			EventID = custom_hash(list_field[0])
			Name = custom_hash(list_field[1])
			
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['6'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(EventID)[2:].rjust(16, '0'), 
				hex(Name)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return