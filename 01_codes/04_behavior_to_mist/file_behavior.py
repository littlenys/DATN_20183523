from util import custom_hash
from util import convert_to_int
from util import int_to_bytes

from pathlib import Path

class DeviceIO:
	def __init__(self, file_beh: dict):
		file_beh['deviceIO']['table']
		self.item_list = {}
		for each_items in file_beh['deviceIO']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			device_path = custom_hash(list_field[0])
			control_io = convert_to_int(list_field[1])
			input_buffer = custom_hash(list_field[2])
			output_buffer = custom_hash(list_field[3])
			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['1', '1', '|', hex(symbol)[2:], hex(control_io)[2:], hex(input_buffer)[2:], hex(output_buffer)[2:], hex(completion)[2:], hex(count)[2:], hex(source_addr)[2:], hex(device_path)[2:]])
			self.item_list[bID] = item_str

class DirectoryQueried:
	def __init__(self, file_beh: dict):
		file_beh['directoryQueried']['table']
		self.item_list = {}
		for each_items in file_beh['directoryQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			file_path = custom_hash(list_field[0])
			disposition = custom_hash(list_field[1])
			file_mask = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['1', '2', '|', hex(symbol)[2:], hex(file_path)[2:], hex(disposition)[2:], hex(file_mask)[2:], hex(completion)[2:], hex(count)[2:], hex(source_addr)[2:]])
			self.item_list[bID] = item_str

class FileAttributesQueried:
	def __init__(self, file_beh: dict):
		file_beh['fileAttributesQueried']['table']
		self.item_list = {}
		for each_items in file_beh['fileAttributesQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			file_path = Path(list_field[0])
			file_name = custom_hash(file_path.name)
			extension = custom_hash(file_path.suffix)
			parent_path = str(file_path.parent)
			parent_path_hash = custom_hash(parent_path)

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['1', '3', '|', hex(symbol)[2:], hex(file_name)[2:], hex(extension)[2:], hex(parent_path_hash)[2:], hex(completion)[2:], hex(count)[2:], hex(source_addr)[2:]])
			self.item_list[bID] = item_str

class FileCopied:
	def __init__(self, file_beh: dict):
		file_beh['fileCopied']['table']
		self.item_list = {}
		for each_items in file_beh['fileCopied']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			new_file = Path(list_field[1])
			new_file_name = custom_hash(new_file.name)
			new_file_suffix = custom_hash(new_file.suffix)
			new_file_hash = custom_hash(str(new_file))
			new_file_parent = custom_hash(str(new_file.parent))

			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['1', '4', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(new_file_name)[2:], 
				hex(new_file_suffix)[2:], 
				hex(new_file_hash)[2:], 
				hex(new_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileCreated:
	def __init__(self, file_beh: dict):
		file_beh['fileCreated']['table']
		self.item_list = {}
		for each_items in file_beh['fileCreated']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			access = 0
			if 'read' in list_field[1]:
				access |= 1

			if 'write' in list_field[1]:
				access |= (1 << 1)

			if 'synchronize' in list_field[1]:
				access |= (1 << 2)
			
			if 'execute' in list_field[1]:
				access |= (1 << 3)


			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['1', '5', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(access)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileDeleted:
	def __init__(self, file_beh: dict):
		file_beh['fileDeleted']['table']
		self.item_list = {}
		for each_items in file_beh['fileDeleted']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			completion = 0x1 if 'success' in list_field[1] else 0x0
			count = convert_to_int(list_field[2])
			source_addr = convert_to_int(list_field[3])
			symbol = custom_hash(list_field[4])

			item_str = ' '.join(['1', '6', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileMoved:
	def __init__(self, file_beh: dict):
		file_beh['fileMoved']['table']
		self.item_list = {}
		for each_items in file_beh['fileMoved']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			new_file = Path(list_field[1])
			new_file_name = custom_hash(new_file.name)
			new_file_suffix = custom_hash(new_file.suffix)
			new_file_hash = custom_hash(str(new_file))
			new_file_parent = custom_hash(str(new_file.parent))

			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['1', '7', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(new_file_name)[2:], 
				hex(new_file_suffix)[2:], 
				hex(new_file_hash)[2:], 
				hex(new_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileOpened:
	def __init__(self, file_beh: dict):
		file_beh['fileOpened']['table']
		self.item_list = {}
		for each_items in file_beh['fileOpened']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			access = 0
			if 'read' in list_field[1]:
				access |= 1

			if 'write' in list_field[1]:
				access |= (1 << 1)

			if 'synchronize' in list_field[1]:
				access |= (1 << 2)
			
			if 'execute' in list_field[1]:
				access |= (1 << 3)

			content_overwritten = 0x1 if 'false' in list_field[3] else 0x0
			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['1', '8', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(access)[2:], 
				hex(content_overwritten)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileOtherOp:
	def __init__(self, file_beh: dict):
		file_beh['fileOtherOp']['table']
		self.item_list = {}
		for each_items in file_beh['fileOtherOp']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = custom_hash(list_field[0])
			data = custom_hash(list_field[2])
			completion = 0x1 if 'success' in list_field[4] else 0x0
			count = convert_to_int(list_field[5])
			source_addr = convert_to_int(list_field[6])
			symbol = custom_hash(list_field[7])

			item_str = ' '.join(['1', '9', '|', 
				hex(symbol)[2:], 
				hex(old_file)[2:], 
				hex(data)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileRead:
	def __init__(self, file_beh: dict):
		file_beh['fileRead']['table']
		self.item_list = {}
		for each_items in file_beh['fileRead']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			offset = 0 if 'unknown' in list_field[1] else convert_to_int(list_field[1])
			length = convert_to_int(list_field[2])
			completion = 0x1 if 'success' in list_field[3] else 0x0
			count = convert_to_int(list_field[4])
			source_addr = convert_to_int(list_field[5])
			symbol = custom_hash(list_field[6])

			item_str = ' '.join(['1', '10', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(offset)[2:], 
				hex(length)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class FileWritten:
	def __init__(self, file_beh: dict):
		file_beh['fileWritten']['table']
		self.item_list = {}
		for each_items in file_beh['fileWritten']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))

			offset = 0 if 'unknown' in list_field[1] else convert_to_int(list_field[1])
			length = convert_to_int(list_field[2])
			value = custom_hash(list_field[3])
			completion = 0x1 if 'success' in list_field[5] else 0x0
			count = convert_to_int(list_field[6])
			source_addr = convert_to_int(list_field[7])
			symbol = custom_hash(list_field[8])

			item_str = ' '.join(['1', '11', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(offset)[2:], 
				hex(length)[2:], 
				hex(value)[2:],
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return

class VolumeInformationQueried:
	def __init__(self, file_beh: dict):
		file_beh['volumeInformationQueried']['table']
		self.item_list = {}
		for each_items in file_beh['volumeInformationQueried']['items']:
			list_field = each_items['fields']
			bID = each_items['id']
			item_str = ''

			old_file = Path(list_field[0])
			old_file_name = custom_hash(old_file.name)
			old_file_suffix = custom_hash(old_file.suffix)
			old_file_hash = custom_hash(str(old_file))
			old_file_parent = custom_hash(str(old_file.parent))
			completion = 0x1 if 'success' in list_field[2] else 0x0
			count = convert_to_int(list_field[3])
			source_addr = convert_to_int(list_field[4])
			symbol = custom_hash(list_field[5])

			item_str = ' '.join(['1', '12', '|', 
				hex(symbol)[2:], 
				hex(old_file_name)[2:], 
				hex(old_file_suffix)[2:], 
				hex(old_file_hash)[2:], 
				hex(old_file_parent)[2:], 
				hex(completion)[2:], 
				hex(count)[2:], 
				hex(source_addr)[2:]])
			self.item_list[bID] = item_str
		return