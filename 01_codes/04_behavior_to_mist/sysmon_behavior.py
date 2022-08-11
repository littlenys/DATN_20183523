from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class Eventlog:
	def __init__(self, file_beh: dict):
		file_beh['eventlog']['table']
		self.item_list = {}
		for each_items in file_beh['eventlog']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			status = custom_hash(list_field[0])
			privilege = custom_hash(list_field[1])
			Data = custom_hash(list_field[2])

			item_str = ' '.join(['16'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(status)[2:].rjust(16, '0'), 
				hex(privilege)[2:].rjust(16, '0'), 
				hex(Data)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return