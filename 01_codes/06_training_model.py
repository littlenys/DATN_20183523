from os import listdir
from os.path import isfile, join, abspath, exists
import pickle
import ujson
from collections import Counter
import numpy as np

class Malware_vector_info:
    def __init__(self, name = "", mitre_level2_vector= []):
        self.name = name
        self.mitre_level2_vector = mitre_level2_vector

path_MIST =  "D:/LEARN/LEARN/DATN/02_resources/vector_MIST_UNMISMAC/"
path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
path_load = "D:/LEARN/LEARN/DATN/02_resources/data_train/"

with open(f"{path_load}behavior_bag_1arg_54_23616.pkl", 'rb') as f:
    MIST_bag = pickle.load(f)
print(len(MIST_bag))

with open(path_load + '01_malware_to_vectorlv2_listtype.pkl', 'rb') as f:
    list_malware_vector = pickle.load(f)

print(list_malware_vector[0])
vector_MIST_names = listdir(path_MIST)



# mlp for multi-label classification
from numpy import mean
from numpy import std
from sklearn.model_selection import RepeatedKFold
from keras.models import Sequential
from keras.layers import Dense
from sklearn.metrics import accuracy_score
 
# get the dataset
def get_dataset():
	print("===============load data===================")
	X = []
	y = []
	for name_and_MITRE in list_malware_vector:
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

	print(f"input: {len(X)} samples")
	return np.array(X), np.array(y)

def save_dataset(path_save):
	print("===============load data===================")
	all_data = []
	for i,name_and_MITRE in enumerate(list_malware_vector):
		print(i)
		name = name_and_MITRE[0].split("-")[-1]
		mitre = name_and_MITRE[1]
		if exists(f"{path_MIST}{name}_vectorMIST.pkl"):
			with open(f"{path_MIST}{name}_vectorMIST.pkl", 'rb') as f:
				vector = pickle.load(f)
			#print(vector)
			all_data.append([name, vector, mitre ])
	print(f"input: {len(all_data)} samples")
	with open(path_save + f'data_final_{len(MIST_bag)}_UNMISMAC.pkl', 'wb') as f:
		pickle.dump(all_data, f)
	return 0
# get the model
def get_model(n_inputs, n_outputs):
	model = Sequential()
	model.add(Dense(64, input_dim=n_inputs, kernel_initializer='he_uniform', activation='relu'))
	model.add(Dense(n_outputs, activation='sigmoid'))
	model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
	return model
 
# evaluate a model using repeated k-fold cross-validation
def evaluate_model(X, y, savepath):
	results = list()
	n_inputs, n_outputs = X.shape[1], y.shape[1]
	# define evaluation procedure
	cv = RepeatedKFold(n_splits=2, n_repeats=3, random_state=1)
	# enumerate folds
	for train_ix, test_ix in cv.split(X):
		# prepare data
		X_train, X_test = X[train_ix], X[test_ix]
		y_train, y_test = y[train_ix], y[test_ix]

		print(f"Train : {len(X_train)}  samples")
		print(f"Test : {len(X_test)}  samples")
		# define model
		model = get_model(n_inputs, n_outputs)
		# fit model
		epochs = 20
		batch_size = 2
		model.fit(X_train, y_train, verbose=1, epochs=epochs, batch_size=batch_size)

		model_json = model.to_json()
		with open(f"{savepath}model_eps_{epochs}_bz_{batch_size}.json", "w") as json_file:
			json_file.write(model_json)
		# serialize weights to HDF5
		model.save_weights(f"{savepath}model_eps_{epochs}_bz_{batch_size}.h5")
		print("Saved model to disk")



		# make a prediction on the test set
		yhat = model.predict(X_test)
		# round probabilities to class labels
		yhat = yhat.round()
		# calculate accuracy
		acc = accuracy_score(y_test, yhat)
		# store result
		print('>%.3f' % acc)
		results.append(acc)
	# serialize model to JSON

	return results
 
# load dataset
save_dataset("D:/LEARN/LEARN/DATN/02_resources/data_train/")
#X, y = get_dataset()


# evaluate model
savepath = "D:/LEARN/LEARN/DATN/02_resources/06_model_result/"
#results = evaluate_model(X, y, savepath)
# summarize performance
print('Accuracy: %.3f (%.3f)' % (mean(results), std(results)))