from numpy import mean
from numpy import std
from sklearn.model_selection import RepeatedKFold
from keras.models import Sequential
from keras.layers import Dense
from sklearn.metrics import accuracy_score
from keras.models import Sequential, model_from_json
from keras.layers import Dense
import pickle
from os import listdir
import numpy as np




path_MIST =  "D:/LEARN/LEARN/DATN/02_resources/vector_MIST/"
path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
path_load = "D:/LEARN/LEARN/DATN/02_resources/data_train/"

with open(f"{path_load}behavior_bag_final_53_3773460.pkl", 'rb') as f:
    MIST_bag = pickle.load(f)
print(len(MIST_bag))

with open(path_load + '01_malware_to_vectorlv2_listtype.pkl', 'rb') as f:
    list_malware_vector = pickle.load(f)
	
with open(path_load + 'data_final.pkl', 'rb') as f:
    data_all = pickle.load(f)
print(f"all data : {len(data_all)}")
print(data_all[1][0])

print(len(list_malware_vector))
print(list_malware_vector[0])
vector_MIST_names = listdir(path_MIST)

X = []
y = []
for name_and_MITRE in list_malware_vector[400:500]:
	name = name_and_MITRE[0].split("-")[-1]
	mitre = name_and_MITRE[1]
	empty_vector = [0]*len(MIST_bag)
	with open(f"{path_MIST}{name}_vectorMIST.pkl", 'rb') as f:
		vector = pickle.load(f)
	#print(vector)
	for value in vector:
		empty_vector[value[0]] = value[1]
	y.append(empty_vector)
	X.append(mitre)

X = np.array(X)
print(f"input: {len(X)} samples")

loaded_model.compile(loss='binary_crossentropy', optimizer='adam')

for X_test in X[0:10]:
    result = loaded_model.predict(X_test)
    print(len(result))

# load json and create model
pathmodel = "D:/LEARN/LEARN/DATN/02_resources/06_model_result/"
name = "model_eps_10_bz_2"
# json_file = open(f'{pathmodel}{name}.json', 'r')
# loaded_model_json = json_file.read()
# json_file.close()
# loaded_model = model_from_json(loaded_model_json)
# load weights into new model
loaded_model = Sequential()
loaded_model.add(Dense(191, input_dim=n_inputs, kernel_initializer='he_uniform', activation='relu'))
loaded_model.add(Dense(191, activation='sigmoid'))
loaded_model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
loaded_model.load_weights(f'{pathmodel}{name}.h5')
print("Loaded model from disk")