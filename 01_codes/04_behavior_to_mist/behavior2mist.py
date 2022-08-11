from operator import countOf
from os import access
import ujson
from pathlib import Path
import re
from dataclasses import dataclass

from util import custom_hash
from util import convert_to_int
from util import int_to_bytes
import traceback

import importlib

def get_ID_from_MD5(processTreeJson):
	list_processes = [processTreeJson]
	result = {}
	while len(list_processes) != 0:
		processes = list_processes.pop()
		for key in processes.keys():
			result[processes[key]['MD5']] = key
			list_processes.append(processes[key]['child'])
	return result

def get_ID_from_PID(processTreeJson):
	list_processes = [processTreeJson]
	result = {}
	while len(list_processes) != 0:
		processes = list_processes.pop()
		for key in processes.keys():
			result[processes[key]['PID']] = key
			list_processes.append(processes[key]['child'])
	return result

def main():
	path = Path(r'C:\crawl_data\mitre_data_new2\mitre_data_new')
	path2 = Path(r'C:\crawl_data\mitre_data_new2\mist')
	path2.mkdir(parents=True, exist_ok=True)
	process_tree_files = path.glob('*-processTree.json')
	regex = re.compile(r'(.*)-processTree.json')
	for each_file in process_tree_files:
		file_name = regex.match(each_file.name).group(1)

		beha = path / Path(file_name + '-behavior.json')
		sign = path / Path(file_name + '-signature.json')
		mitre = path / Path(file_name + '-mitre.json')
		tree =  path/ Path(file_name + '-processTree.json')

		behavior_json = ujson.decode(beha.open('r').read())
		sig_json = ujson.decode(sign.open('r').read())
		mitre_json = ujson.decode(mitre.open('r').read())
		process_tree_json = ujson.decode(tree.open('r').read())
		md5_to_id = get_ID_from_MD5(process_tree_json)
		pid_to_id = get_ID_from_PID(process_tree_json)
		result = {}

		for each_sign in sig_json.keys():
			result[each_sign] = []
			bID = sig_json[each_sign]['behavior_id']
			activities = sig_json[each_sign]['data_activity']
			sections = sig_json[each_sign]['data_section']
			if sections == 'sectionUnloaded':
				continue
			if sections == 'atomAdded':
				continue

			header = sig_json[each_sign]['signature_header']
			pid_md5 = sig_json[each_sign]['pid_md5']
			md5 = pid_md5[-32:]
			pid = pid_md5[:-32]
			list_activity = activities.split(' ')
			list_section = sections.split(' ')

			for k, activity in enumerate(list_activity):
				if activity[:-10] == 'mutant':
					activity = 'mutex' + activity[-10:]
					list_section[k] = 'mutex' + list_section[k][6:]

				if activity[:-10] == 'time':
					activity = 'timing' + activity[-10:]

				try:
					module = importlib.import_module(f'{activity[:-10]}_behavior')
				except:
					print(beha.name)
					traceback.print_exc()
					exit()
				section = list_section[k]
				behavior_id = 0
				try:
					if md5 in md5_to_id:
						behavior_id = md5_to_id[md5]
					else:
						behavior_id = pid_to_id[pid]
				except:
					continue

				if section == 'sectionLoaded':
					behavior_class = getattr(module, section[0].upper() + section[1:] + 'W')
					result[each_sign].append(behavior_class(behavior_json[md5_to_id[md5]][activity[:-10]]['activities']).item_list)
					behavior_class = getattr(module, section[0].upper() + section[1:] + 'P')
					result[each_sign].append(behavior_class(behavior_json[md5_to_id[md5]][activity[:-10]]['activities']).item_list)
					continue

				behavior_class = getattr(module, section[0].upper() + section[1:])
				try:
					result[each_sign].append(behavior_class(behavior_json[md5_to_id[md5]][activity[:-10]]['activities']).item_list)
				except Exception as e:
					print(beha.name)
					traceback.print_exc()
					exit()

		mitre_dict = ujson.decode(mitre.open('r').read())
		mitre_result = {}
		for each_mitre in mitre_dict.keys():
			mitre_result[each_mitre] = []
			for each_sign in mitre_dict[each_mitre]['signatures']:
				if each_sign in result:
					dict_list = [x[i] for x in result[each_sign] for i in x]
					mitre_result[each_mitre] +=  dict_list

		output = path2 / Path(file_name + '-mitreMist.json')
		output.touch(exist_ok=True)
		with output.open('w') as f:
			ujson.dump(mitre_result, f)
	pass

if __name__ == '__main__':
	main()