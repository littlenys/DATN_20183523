from os import listdir, path
from os.path import isfile, join, abspath
import pickle
from numpy import empty
from pandas import array
import ujson
from collections import Counter
import random



path_behavior = "D:/LEARN/LEARN/DATN/02_resources/mist_behavior/"
path_load = "D:/LEARN/LEARN/DATN/02_resources/data_train/"
path_mist = "D:/LEARN/LEARN/DATN/02_resources/"
path_save = "D:/LEARN/LEARN/DATN/02_resources/vector_MIST_UNMISMAC/"
# with open(path_load + 'behavior_bag_raw.pkl', 'rb') as f:
#     behavior_bag = pickle.load(f)

# flatten_list = lambda y:[x for a in y for x in flatten_list(a)] if type(y) is list else [y]
# behavior_bag = flatten_list(behavior_bag)
# print(len(behavior_bag))
# behavior_bag = list(set(behavior_bag))
# print(f"final bag : {len(behavior_bag)}")

# with open(f"{path_load}behavior_bag_final_53_3773460.pkl", 'wb') as f:
#     pickle.dump(behavior_bag, f)


with open(f"{path_load}behavior_bag_1arg_54_23616.pkl", 'rb') as f:
    MIST_bag = pickle.load(f)
print(len(MIST_bag))
print(MIST_bag[3])

# suffle to UNMISMAC
random.shuffle(MIST_bag)
random.shuffle(MIST_bag)
random.shuffle(MIST_bag)
#embedding
list_MIST = listdir(path_behavior)
print(len(list_MIST))
print(list_MIST[2])
#for mist in MIST_bag:

print("================== START=====================")
dict_MIST_bag_index = dict()
for i, mist in enumerate(MIST_bag):
    dict_MIST_bag_index[mist] = i

start_index = 0
stop_index = 10
for i,text_name in enumerate(list_MIST):
    print(i)
    
    name = text_name.split("-")[-2]
    print(name)
    if not (path.exists(f"{path_save}{name}_vectorMIST.pkl")):
        empty_vector = [0]*len(MIST_bag)
        f = open(path_behavior + text_name, "r")
        text = f.read()
        f.close()
        behaviors = text.split('\n')
    
        print(f"{i + start_index} {name} : {len(behaviors)}")
        unmatch_behavior = 0
        for behavior in behaviors:
            try:
                behavior = " ".join(behavior.split(" ")[0:4])
                empty_vector[dict_MIST_bag_index[behavior]] +=1
            except:
                unmatch_behavior +=1
        print(sum(empty_vector))
        print(unmatch_behavior)
        #print(empty_vector)

        match_index = []
        for index, item in enumerate(empty_vector):
            if item > 0:
                match_index.append([index, item])

        with open(f"{path_save}{name}_vectorMIST.pkl", 'wb') as f:
            pickle.dump(match_index, f)