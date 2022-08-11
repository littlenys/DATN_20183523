from inspect import signature
import numpy as np
from collections import Counter
from os import listdir
from os.path import isfile, join
import glob, os
import pickle


path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/"
path_save = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
list_mitre=[]
list_behavior = []
list_processTree = []
list_signature = []
os.chdir(path_data)
files = glob.glob("*.json")
print(f"total: {len(files)}")
#print(files[1])

for file in files:
    loai = file.split('.')[-2].split('-')[-1]
    #print(loai)
    if loai == "mitre":
        list_mitre.append(file)
    elif loai == "behavior":
        list_behavior.append(file)
    elif loai == "processTree":
        list_processTree.append(file)
    elif loai == "signature":
        list_signature.append(file)

# print(f"list_mitre : {len(list_mitre)}")
# print(f"list_behavior : {len(list_behavior)}")
# print(f"list_processTree : {len(list_processTree)}")
# print(f"list_signature : {len(list_signature)}")

#1. Check filename
list_name = []
for i, fullname in enumerate(list_mitre):
    name = fullname.split("-")
    name = "-".join(name[:len(name)-1])
    if name not in list_name:
        list_name.append(name)
for i, fullname in enumerate(list_behavior):
    name = fullname.split("-")
    name = "-".join(name[:len(name)-1])
    if name not in list_name:
        list_name.append(name)
for i, fullname in enumerate(list_processTree):
    name = fullname.split("-")
    name = "-".join(name[:len(name)-1])
    if name not in list_name:
        list_name.append(name)
for i, fullname in enumerate(list_signature):
    name = fullname.split("-")
    name = "-".join(name[:len(name)-1])
    if name not in list_name:
        list_name.append(name)

missing = []
for name in list_name:
    if (str(name + "-behavior.json") not in list_behavior):
        missing.append(name)
    if (str(name + "-processTree.json") not in list_processTree):
        missing.append(name)
    if (str(name + "-signature.json") not in list_signature):
        missing.append(name)
    if (str(name + "-mitre.json") not in list_mitre):
        missing.append(name)
print(f"name: {len(list_name)}")
print(f"missing: {len(missing)}")

#2. Remove if file name missing
for name in missing:
    if os.path.exists(path_data + name + "-behavior.json"):
        os.remove(path_data + name + "-behavior.json")
    if os.path.exists(path_data + name + "-processTree.json"):
        os.remove(path_data + name + "-processTree.json")
    if os.path.exists(path_data + name + "-signature.json"):
        os.remove(path_data + name + "-signature.json")
    if os.path.exists(path_data + name + "-mitre.json"):
        os.remove(path_data + name + "-mitre.json")
    list_name.remove(name)

with open(path_save + '00_list_malware_name.pkl', 'wb') as f:
    pickle.dump(list_name, f)

