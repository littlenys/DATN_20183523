from os import listdir
from os.path import isfile, join, abspath
import pickle
from math import pi
import pandas as pd
from bokeh.palettes import Category20c, Viridis, Viridis256, viridis, brewer, magma, turbo, plasma
from bokeh.plotting import figure, show, output_file, save
from bokeh.transform import cumsum
from collections import Counter 
import itertools

class Malware:
    def __init__(self, name = "", labels = [], format = "EXE", accuracy = "mal100"):
        self.name = name
        self.labels = labels
        self.format = format
        self.accuracy = accuracy

# 2. Visualize format
def visualize_pie_chart(list_info = [], savepath = "D:/visualize/visualize_format.html", num = 10, palettes = magma(10) ):
    x = dict(Counter(list_info))
    x = dict(sorted(x.items(), key=lambda item: item[1], reverse=True))
    total = sum(list(x.values()))
    other = total
    x = dict(itertools.islice(x.items(), num))
    other -= sum(list(x.values()))
    x['other'] = other
    #print(x)S
    data = pd.Series(x).reset_index(name='value').rename(columns={'index': 'country'})
    data['angle'] = data['value']/data['value'].sum() * 2*pi
    data['color'] = palettes

    p = figure(height=400, title= savepath, toolbar_location=None,
            tools="hover", tooltips="@country: @value", x_range=(-0.5, 1.0))

    p.wedge(x=0, y=1, radius=0.4,
            start_angle=cumsum('angle', include_zero=True), end_angle=cumsum('angle'),
            line_color="white", fill_color='color', legend_field='country', source=data)

    p.axis.axis_label = None
    p.axis.visible = False
    p.grid.grid_line_color = None

    output_file(filename=savepath, title="Static HTML file")
    save(p)

def render_table():
    return 0

if __name__ == "__main__":
    # 1. Load data
    path_save_html = "D:/LEARN/LEARN/DATN/02_resources/visualize/html/"
    path_data = "D:/LEARN/LEARN/DATN/02_resources/mitre_data_new/converted_data/"
    with open(path_data + '00_list_malware_name.pkl', 'rb') as f:
        list_malware_name = pickle.load(f)

    list_info_Malware = []
    for fullname in list_malware_name[:]:
        name = fullname.split("-")[-1]
        format = fullname.split("-")[0].split(".")[-1]
        labels = fullname.split("-")[0].split(".")[1:-1]
        accuracy = fullname.split("-")[0].split(".")[0]
        list_info_Malware.append(Malware(name, labels, format, accuracy ))

    list_format = []
    print(len(list_info_Malware))
    for info in list_info_Malware:
        list_format.append( info.format )
    visualize_pie_chart(list_format, path_save_html + "list_format.html", num=14, palettes= magma(15) )

    list_len_labels = []
    print(len(list_info_Malware))
    for info in list_info_Malware:
        list_len_labels.append( len(info.labels) )

    list_labels = []
    print(len(list_info_Malware))
    for info in list_info_Malware:
        list_labels.append( str(info.labels))
    visualize_pie_chart(list_labels, path_save_html + "list_labels.html", num=15 , palettes= viridis(16))

    list_accuracy = []
    print(len(list_info_Malware))
    for info in list_info_Malware:
        list_accuracy.append( str(info.accuracy))
    visualize_pie_chart(list_accuracy, path_save_html + "list_accuracy.html", num=15 , palettes= viridis(16))


