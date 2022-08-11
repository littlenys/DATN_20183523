from inspect import signature
import numpy as np
from collections import Counter
from os import listdir
from os.path import isfile, join, getsize
import glob, os
import pickle


path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/"
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

totalGb = 0
total = 0
for name in list_mitre:
    total += getsize(path_data + name)
print(f"mitre : {total/1024/len(list_mitre)} Kb")
totalGb += total

total = 0
for name in list_behavior:
    total += getsize(path_data + name)
print(f"behavior : {total/1024/len(list_mitre)} Kb")
totalGb += total
total = 0
for name in list_signature:
    total += getsize(path_data + name)
print(f"signature : {total/1024/len(list_mitre)} Kb")
totalGb += total

print(f"Total : {totalGb/1024/1024/1024} Gb")