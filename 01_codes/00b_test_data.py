from os import listdir
from os.path import isfile, join, abspath
import pickle
import ujson
from collections import Counter

Malwares_info = []
list_Malwares_info = []
path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/"
path_save = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
with open(path_data + 'converted_data/list_malware_name.pkl', 'rb') as f:
    list_malware_name = pickle.load(f)
#print(len(list_malware_name))
#load mitre files
false_tag = []
for i , name in enumerate(list_malware_name[0:1]):

    blank_mitre_level2_vector = 191*[0]
    print(f"{i} :  {name}" )

    #print(path_data + name + "-mitre.json")
    f = open(path_data + name + "-mitre.json" )
    data = ujson.load(f)
    f.close()
    keys = data.keys()
    print(keys)
    #print(len(keys))
    total = 0
    for key in keys:
        try:
            if data[key]['signature_len'] > 0:
                #print(key)s
                total += 1
                print(key)
                blank_mitre_level2_vector[INDEX_DIC_MITRE_LEVEL2_VECTOR[DICT_LEVEL23_TO_LEVEL2[key]]] = 1
        except:
            false_tag.append(key)
    
    print(total)