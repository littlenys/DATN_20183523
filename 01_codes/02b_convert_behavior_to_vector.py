from os import listdir
from os.path import isfile, join, abspath
import pickle
import ujson
from collections import Counter


path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/"
path_save = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
with open(path_data + 'converted_data/list_malware_name.pkl', 'rb') as f:
    list_malware_name = pickle.load(f)

for i , name in enumerate(list_malware_name[0:500]):

    print(i)
    #print(path_data + name + "-mitre.json")
    f = open(path_data + name + "-behavior.json" )
    data = ujson.load(f)
    f.close()