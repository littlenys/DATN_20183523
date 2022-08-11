from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class DesktopCreated:
	def __init__(self, file_beh: dict):
		file_beh['desktopCreated']['table']
		self.item_list = {}
		for each_items in file_beh['desktopCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '1'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class ForegroundWindowGot:
	def __init__(self, file_beh: dict):
		file_beh['foregroundWindowGot']['table']
		self.item_list = {}
		for each_items in file_beh['foregroundWindowGot']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '2'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InputBlocked:
	def __init__(self, file_beh: dict):
		file_beh['inputBlocked']['table']
		self.item_list = {}
		for each_items in file_beh['inputBlocked']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '3'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class InputSent:
	def __init__(self, file_beh: dict):
		file_beh['inputSent']['table']
		self.item_list = {}
		for each_items in file_beh['inputSent']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '4'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class KeyStateQueried:
	def __init__(self, file_beh: dict):
		file_beh['keyStateQueried']['table']
		self.item_list = {}
		for each_items in file_beh['keyStateQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '5'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowDestroyed:
	def __init__(self, file_beh: dict):
		file_beh['windowDestroyed']['table']
		self.item_list = {}
		for each_items in file_beh['windowDestroyed']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			name = custom_hash(list_field[0])

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['13'.rjust(2, '0'), '6'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(name)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MessagePosted:
	def __init__(self, file_beh: dict):
		file_beh['messagePosted']['table']
		self.item_list = {}
		for each_items in file_beh['messagePosted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			hwnd = convert_to_int(list_field[0])
			message = custom_hash(list_field[1])
			wparam = custom_hash(list_field[2])
			lparam = custom_hash(list_field[3])

			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['13'.rjust(2, '0'), '7'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(hwnd)[2:].rjust(8, '0'),
				hex(message)[2:].rjust(16, '0'),
				hex(wparam)[2:].rjust(16, '0'),
				hex(lparam)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class MessageThreadPosted:
	def __init__(self, file_beh: dict):
		file_beh['messageThreadPosted']['table']
		self.item_list = {}
		for each_items in file_beh['messageThreadPosted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			hwnd = convert_to_int(list_field[0])
			message = custom_hash(list_field[1])
			wparam = custom_hash(list_field[2])
			lparam = custom_hash(list_field[3])

			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['13'.rjust(2, '0'), '8'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(hwnd)[2:].rjust(8, '0'),
				hex(message)[2:].rjust(16, '0'),
				hex(wparam)[2:].rjust(16, '0'),
				hex(lparam)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowCreated:
	def __init__(self, file_beh: dict):
		file_beh['windowCreated']['table']
		self.item_list = {}
		for each_items in file_beh['windowEnumerated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			hwnd = convert_to_int(list_field[2])
			message = custom_hash(list_field[0])
			wparam = custom_hash(list_field[1])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['13'.rjust(2, '0'), '9'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(hwnd)[2:].rjust(8, '0'),
				hex(message)[2:].rjust(16, '0'),
				hex(wparam)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowEnumerated:
	def __init__(self, file_beh: dict):
		file_beh['windowEnumerated']['table']
		self.item_list = {}
		for each_items in file_beh['windowEnumerated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			desktop_hwnd = convert_to_int(list_field[0])
			parent_hwnd = convert_to_int(list_field[1])
			enum_child = custom_hash(list_field[2])
			tid = convert_to_int(list_field[3])
			window_handle = convert_to_int(list_field[4])

			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['13'.rjust(2, '0'), '10'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(desktop_hwnd)[2:].rjust(8, '0'),
				hex(parent_hwnd)[2:].rjust(8, '0'),
				hex(enum_child)[2:].rjust(16, '0'),
				hex(tid)[2:].rjust(8, '0'),
				hex(window_handle)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowFound:
	def __init__(self, file_beh: dict):
		file_beh['windowFound']['table']
		self.item_list = {}
		for each_items in file_beh['windowFound']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			window_name = custom_hash(list_field[0])
			class_name = custom_hash(list_field[1])
			hwnd = convert_to_int(list_field[2])

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['13'.rjust(2, '0'), '11'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(window_name)[2:].rjust(16, '0'),
				hex(class_name)[2:].rjust(16, '0'),
				hex(hwnd)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowPlacementGot:
	def __init__(self, file_beh: dict):
		file_beh['windowPlacementGot']['table']
		self.item_list = {}
		for each_items in file_beh['windowPlacementGot']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			command = custom_hash(list_field[1])
			hwnd = convert_to_int(list_field[0])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['13'.rjust(2, '0'), '12'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(command)[2:].rjust(16, '0'),
				hex(hwnd)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowPlacementSet:
	def __init__(self, file_beh: dict):
		file_beh['windowPlacementSet']['table']
		self.item_list = {}
		for each_items in file_beh['windowPlacementSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			command = custom_hash(list_field[1])
			hwnd = convert_to_int(list_field[0])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['13'.rjust(2, '0'), '13'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(command)[2:].rjust(16, '0'),
				hex(hwnd)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowShown:
	def __init__(self, file_beh: dict):
		file_beh['windowShown']['table']
		self.item_list = {}
		for each_items in file_beh['windowShown']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			command = custom_hash(list_field[1])
			hwnd = convert_to_int(list_field[0])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['13'.rjust(2, '0'), '14'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(command)[2:].rjust(16, '0'),
				hex(hwnd)[2:].rjust(8, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return

class WindowsHookSet:
	def __init__(self, file_beh: dict):
		file_beh['windowsHookSet']['table']
		self.item_list = {}
		for each_items in file_beh['windowsHookSet']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			module = custom_hash(list_field[0])
			tid = convert_to_int(list_field[1])
			hook_code = custom_hash(list_field[2])

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['13'.rjust(2, '0'), '15'.rjust(2, '0'), '|', 
				hex(symbol)[2:].rjust(16, '0'), 
				hex(module)[2:].rjust(16, '0'),
				hex(tid)[2:].rjust(8, '0'),
				hex(hook_code)[2:].rjust(16, '0'),
				hex(completion)[2:].rjust(2, '0'), 
				hex(count)[2:].rjust(4, '0'), 
				hex(source_addr)[2:].rjust(16, '0')])
			self.item_list[bID] = item_str
		return