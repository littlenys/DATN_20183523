from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class Javaactivities:
	def __init__(self, file_beh: dict):
		file_beh['javaactivities']['table']
		self.item_list = {}
		for each_items in file_beh['javaactivities']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			thread_id = convert_to_int(list_field[0])
			API = custom_hash(list_field[1])
			argument = custom_hash(list_field[2])
			return_java = custom_hash(list_field[3])

			item_str = ' '.join(['13'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(thread_id)[2:].rjust(8, '0'), 
				hex(API)[2:].rjust(16, '0'),
				hex(argument)[2:].rjust(16, '0'),
				hex(return_java)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return