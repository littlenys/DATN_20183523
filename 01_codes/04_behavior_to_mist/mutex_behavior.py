from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class MutexCreated:
	def __init__(self, file_beh: dict):
		file_beh['mutexCreated']['table']
		self.item_list = {}
		for each_items in file_beh['mutexCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['4'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(old_file_name)[2:].rjust(16, '0'), 
				hex(old_file_hash)[2:].rjust(16, '0'), 
				hex(old_file_parent)[2:].rjust(16, '0'), 
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return