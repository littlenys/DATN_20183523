import pickle

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

from bokeh.io import show
from bokeh.models import ColumnDataSource
from bokeh.palettes import Spectral6
from bokeh.plotting import figure
from bokeh.transform import factor_cmap

from bokeh.io import output_file, show
from bokeh.models import Legend
from bokeh.plotting import figure


with open("D:/LEARN/LEARN/DATN/02_resources/data_train/match_tag_2arg_54_441898.pkl", 'rb') as f:
    match_tag = pickle.load(f)

INDEX_DIC_MITRE_LEVEL2_VECTOR = {
    "Active Scanning": 0,
    "Gather Victim Host Information": 1,
    "Gather Victim Identity Information": 2,
    "Gather Victim Network Information": 3,
    "Gather Victim Org Information": 4,
    "Phishing for Information": 5,
    "Search Closed Sources": 6,
    "Search Open Technical Databases": 7,
    "Search Open Websites/Domains": 8,
    "Search Victim-Owned Websites": 9,
    "Acquire Infrastructure": 10,
    "Compromise Accounts": 11,
    "Compromise Infrastructure": 12,
    "Develop Capabilities": 13,
    "Establish Accounts": 14,
    "Obtain Capabilities": 15,
    "Stage Capabilities": 16,
    "Drive-by Compromise": 17,
    "Exploit Public-Facing Application": 18,
    "External Remote Services": 19,
    "Hardware Additions": 20,
    "Phishing": 21,
    "Replication Through Removable Media": 22,
    "Supply Chain Compromise": 23,
    "Trusted Relationship": 24,
    "Valid Accounts": 25,
    "Command and Scripting Interpreter": 26,
    "Container Administration Command": 27,
    "Deploy Container": 28,
    "Exploitation for Client Execution": 29,
    "Inter-Process Communication": 30,
    "Native API": 31,
    "Scheduled Task/Job": 32,
    "Shared Modules": 33,
    "Software Deployment Tools": 34,
    "System Services": 35,
    "User Execution": 36,
    "Windows Management Instrumentation": 37,
    "Account Manipulation": 38,
    "BITS Jobs": 39,
    "Boot or Logon Autostart Execution": 40,
    "Boot or Logon Initialization Scripts": 41,
    "Browser Extensions": 42,
    "Compromise Client Software Binary": 43,
    "Create Account": 44,
    "Create or Modify System Process": 45,
    "Event Triggered Execution": 46,
    "Hijack Execution Flow": 47,
    "Implant Internal Image": 48,
    "Modify Authentication Process": 49,
    "Office Application Startup": 50,
    "Pre-OS Boot": 51,
    "Server Software Component": 52,
    "Traffic Signaling": 53,
    "Abuse Elevation Control Mechanism": 54,
    "Access Token Manipulation": 55,
    "Domain Policy Modification": 56,
    "Escape to Host": 57,
    "Exploitation for Privilege Escalation": 58,
    "Process Injection": 59,
    "Build Image on Host": 60,
    "Debugger Evasion": 61,
    "Deobfuscate/Decode Files or Information": 62,
    "Direct Volume Access": 63,
    "Execution Guardrails": 64,
    "Exploitation for Defense Evasion": 65,
    "File and Directory Permissions Modification": 66,
    "Hide Artifacts": 67,
    "Impair Defenses": 68,
    "Indicator Removal on Host": 69,
    "Indirect Command Execution": 70,
    "Masquerading": 71,
    "Modify Cloud Compute Infrastructure": 72,
    "Modify Registry": 73,
    "Modify System Image": 74,
    "Network Boundary Bridging": 75,
    "Obfuscated Files or Information": 76,
    "Plist File Modification": 77,
    "Reflective Code Loading": 78,
    "Rogue Domain Controller": 79,
    "Rootkit": 80,
    "Subvert Trust Controls": 81,
    "System Binary Proxy Execution": 82,
    "System Script Proxy Execution": 83,
    "Template Injection": 84,
    "Trusted Developer Utilities Proxy Execution": 85,
    "Unused/Unsupported Cloud Regions": 86,
    "Use Alternate Authentication Material": 87,
    "Virtualization/Sandbox Evasion": 88,
    "Weaken Encryption": 89,
    "XSL Script Processing": 90,
    "Adversary-in-the-Middle": 91,
    "Brute Force": 92,
    "Credentials from Password Stores": 93,
    "Exploitation for Credential Access": 94,
    "Forced Authentication": 95,
    "Forge Web Credentials": 96,
    "Input Capture": 97,
    "Multi-Factor Authentication Interception": 98,
    "Multi-Factor Authentication Request Generation": 99,
    "Network Sniffing": 100,
    "OS Credential Dumping": 101,
    "Steal Application Access Token": 102,
    "Steal or Forge Kerberos Tickets": 103,
    "Steal Web Session Cookie": 104,
    "Unsecured Credentials": 105,
    "Account Discovery": 106,
    "Application Window Discovery": 107,
    "Browser Bookmark Discovery": 108,
    "Cloud Infrastructure Discovery": 109,
    "Cloud Service Dashboard": 110,
    "Cloud Service Discovery": 111,
    "Cloud Storage Object Discovery": 112,
    "Container and Resource Discovery": 113,
    "Domain Trust Discovery": 114,
    "File and Directory Discovery": 115,
    "Group Policy Discovery": 116,
    "Network Service Discovery": 117,
    "Network Share Discovery": 118,
    "Password Policy Discovery": 119,
    "Peripheral Device Discovery": 120,
    "Permission Groups Discovery": 121,
    "Process Discovery": 122,
    "Query Registry": 123,
    "Remote System Discovery": 124,
    "Software Discovery": 125,
    "System Information Discovery": 126,
    "System Location Discovery": 127,
    "System Network Configuration Discovery": 128,
    "System Network Connections Discovery": 129,
    "System Owner/User Discovery": 130,
    "System Service Discovery": 131,
    "System Time Discovery": 132,
    "Exploitation of Remote Services": 133,
    "Internal Spearphishing": 134,
    "Lateral Tool Transfer": 135,
    "Remote Service Session Hijacking": 136,
    "Remote Services": 137,
    "Taint Shared Content": 138,
    "Archive Collected Data": 139,
    "Audio Capture": 140,
    "Automated Collection": 141,
    "Browser Session Hijacking": 142,
    "Clipboard Data": 143,
    "Data from Cloud Storage Object": 144,
    "Data from Configuration Repository": 145,
    "Data from Information Repositories": 146,
    "Data from Local System": 147,
    "Data from Network Shared Drive": 148,
    "Data from Removable Media": 149,
    "Data Staged": 150,
    "Email Collection": 151,
    "Screen Capture": 152,
    "Video Capture": 153,
    "Application Layer Protocol": 154,
    "Communication Through Removable Media": 155,
    "Data Encoding": 156,
    "Data Obfuscation": 157,
    "Dynamic Resolution": 158,
    "Encrypted Channel": 159,
    "Fallback Channels": 160,
    "Ingress Tool Transfer": 161,
    "Multi-Stage Channels": 162,
    "Non-Application Layer Protocol": 163,
    "Non-Standard Port": 164,
    "Protocol Tunneling": 165,
    "Proxy": 166,
    "Remote Access Software": 167,
    "Web Service": 168,
    "Automated Exfiltration": 169,
    "Data Transfer Size Limits": 170,
    "Exfiltration Over Alternative Protocol": 171,
    "Exfiltration Over C2 Channel": 172,
    "Exfiltration Over Other Network Medium": 173,
    "Exfiltration Over Physical Medium": 174,
    "Exfiltration Over Web Service": 175,
    "Scheduled Transfer": 176,
    "Transfer Data to Cloud Account": 177,
    "Account Access Removal": 178,
    "Data Destruction": 179,
    "Data Encrypted for Impact": 180,
    "Data Manipulation": 181,
    "Defacement": 182,
    "Disk Wipe": 183,
    "Endpoint Denial of Service": 184,
    "Firmware Corruption": 185,
    "Inhibit System Recovery": 186,
    "Network Denial of Service": 187,
    "Resource Hijacking": 188,
    "Service Stop": 189,
    "System Shutdown/Reboot": 190,
}
#print(match_tag)
'''
match_tag = {
    "Replication Through Removable Media": 51897,
    "Command and Scripting Interpreter": 17824,
    "Exploitation for Client Execution": 142197,
    "Scheduled Task/Job": 1581,
    "Shared Modules": 7923,
    "BITS Jobs": 19,
    "Boot or Logon Autostart Execution": 27827,
    "Browser Extensions": 1063,
    "Create Account": 126,
    "Create or Modify System Process": 3856,
    "Event Triggered Execution": 44,
    "Hijack Execution Flow": 458741,
    "Pre-OS Boot": 11,
    "Exploitation for Privilege Escalation": 1188,
    "Process Injection": 595898,
    "Deobfuscate/Decode Files or Information": 408,
    "File and Directory Permissions Modification": 1829,
    "Hide Artifacts": 380149,
    "Impair Defenses": 3826735,
    "Indicator Removal on Host": 3670,
    "Masquerading": 255394,
    "Modify Registry": 1922,
    "Obfuscated Files or Information": 5545,
    "Subvert Trust Controls": 70,
    "System Binary Proxy Execution": 79,
    "Virtualization/Sandbox Evasion": 1301052,
    "Input Capture": 1514,
    "Network Sniffing": 6,
    "OS Credential Dumping": 1886222,
    "Unsecured Credentials": 1515276,
    "File and Directory Discovery": 573183,
    "Network Share Discovery": 6484,
    "Peripheral Device Discovery": 102042,
    "Process Discovery": 680678,
    "Query Registry": 111932,
    "Remote System Discovery": 154139,
    "Software Discovery": 795692,
    "System Information Discovery": 13200894,
    "System Network Configuration Discovery": 56,
    "System Owner/User Discovery": 40888,
    "System Time Discovery": 6975,
    "Taint Shared Content": 10707,
    "Archive Collected Data": 1485,
    "Clipboard Data": 561,
    "Data from Local System": 2495057,
    "Email Collection": 945042,
    "Data Encoding": 1,
    "Ingress Tool Transfer": 52963,
    "Remote Access Software": 30,
    "Data Encrypted for Impact": 1671,
    "Endpoint Denial of Service": 664,
    "Inhibit System Recovery": 275,
}

{
    "System Information Discovery": 17521,
    "Software Discovery": 16230,
    "Encrypted Channel": 16087,
    "Process Injection": 15747,
    "Obfuscated Files or Information": 15710,
    "Archive Collected Data": 15342,
    "Virtualization/Sandbox Evasion": 14686,
    "Masquerading": 13393,
    "Non-Application Layer Protocol": 11680,
    "File and Directory Discovery": 11637,
    "Deobfuscate/Decode Files or Information": 11373,
    "Process Discovery": 11150,
    "Impair Defenses": 11028,
    "Remote System Discovery": 10587,
    "Ingress Tool Transfer": 9696,
    "Native API": 7541,
    "Application Window Discovery": 7252,
    "OS Credential Dumping": 6656,
    "Data from Local System": 6263,
    "System Time Discovery": 5859,
    "Windows Management Instrumentation": 5399,
    "Application Layer Protocol": 5361,
    "Query Registry": 5243,
    "Non-Standard Port": 4851,
    "Email Collection": 4687,
    "Indicator Removal on Host": 4032,
    "Unsecured Credentials": 3965,
    "Hijack Execution Flow": 3732,
    "Access Token Manipulation": 3665,
    "Clipboard Data": 3338,
    "Hide Artifacts": 3208,
    "Boot or Logon Autostart Execution": 2978,
    "Account Discovery": 2755,
    "System Owner/User Discovery": 2674,
    "Exploitation for Client Execution": 2417,
    "System Shutdown/Reboot": 2392,
    "Input Capture": 2297,
    "Shared Modules": 2286,
    "System Binary Proxy Execution": 2236,
    "Command and Scripting Interpreter": 2111,
    "System Network Configuration Discovery": 1909,
    "Create or Modify System Process": 1405,
    "System Services": 894,
    "Scheduled Task/Job": 738,
    "Rootkit": 690,
    "System Service Discovery": 668,
    "File and Directory Permissions Modification": 657,
    "Modify Registry": 645,
    "Web Service": 597,
    "Screen Capture": 456,
    "Valid Accounts": 442,
    "Remote Access Software": 432,
    "Peripheral Device Discovery": 394,
    "Endpoint Denial of Service": 366,
    "Create Account": 327,
    "Exploitation for Privilege Escalation": 296,
    "Replication Through Removable Media": 126,
    "System Network Connections Discovery": 125,
    "Pre-OS Boot": 121,
    "Data Encoding": 117,
    "Defacement": 93,
    "Data Obfuscation": 91,
    "Proxy": 87,
    "Taint Shared Content": 75,
    "Phishing": 48,
    "Subvert Trust Controls": 48,
    "Data Encrypted for Impact": 43,
    "Drive-by Compromise": 42,
    "Network Share Discovery": 32,
    "Inhibit System Recovery": 30,
    "Event Triggered Execution": 17,
    "Browser Extensions": 15,
    "BITS Jobs": 11,
    "Office Application Startup": 6,
    "Exfiltration Over Alternative Protocol": 6,
    "Exploitation of Remote Services": 4,
    "Network Sniffing": 3,
    "Software Deployment Tools": 1,
    "Remote Services": 1,
}

'''
match_big_tag_ ={
    "System Information Discovery": 17521,
    "Software Discovery": 16230,
    "Encrypted Channel": 16087,
    "Process Injection": 15747,
    "Obfuscated Files or Information": 15710,
    "Archive Collected Data": 15342,
    "Virtualization/Sandbox Evasion": 14686,
    "Masquerading": 13393,
    "Non-Application Layer Protocol": 11680,
    "File and Directory Discovery": 11637,
    "Deobfuscate/Decode Files or Information": 11373,
    "Process Discovery": 11150,
    "Impair Defenses": 11028,
    "Remote System Discovery": 10587,
    "Ingress Tool Transfer": 9696,
    "Native API": 7541,
    "Application Window Discovery": 7252,
    "OS Credential Dumping": 6656,
    "Data from Local System": 6263,
}
match_big_tag_ ={
    "System Information Discovery": 17521,
    "Software Discovery": 16230,
    "Encrypted Channel": 16087,
    "Process Injection": 15747,
    "Obfuscated Files or Information": 15710,
    "Archive Collected Data": 15342,
    "Virtualization/Sandbox Evasion": 14686,
    "Masquerading": 13393,
    "Non-Application Layer Protocol": 11680,
    "File and Directory Discovery": 11637,
    "Deobfuscate/Decode Files or Information": 11373,
    "Process Discovery": 11150,
    "Impair Defenses": 11028,
    "Remote System Discovery": 10587,
    "Ingress Tool Transfer": 9696,
    "Native API": 7541,
    "Application Window Discovery": 7252,
    "OS Credential Dumping": 6656,
    "Data from Local System": 6263,
}



match_big_tag = {
    "Process Injection": 597514,
    "Process Discovery": 685167,
    "Software Discovery": 816038,
    "Email Collection": 916947,
    "Virtualization/Sandbox Evasion": 1321971,
    "Unsecured Credentials": 1505557,
    "OS Credential Dumping": 1902187,
    "Data from Local System": 2544942,
    "Impair Defenses": 3875067,
    "System Information Discovery": 13179746,
}


print(len(match_tag))

# 2. Visualize format
def visualize_pie_chart(list_info = [], savepath = "D:/visualize/visualize_format.html", num = 10, palettes = magma(10) ):
    x = dict(Counter(list_info))
    x = dict(sorted(x.items(), key=lambda item: item[1], reverse=True))
    total = sum(list(x.values()))
    other = total
    x = dict(itertools.islice(x.items(), num))
    other -= sum(list(x.values()))
    x['other'] = other
    #print(x)
    data = pd.Series(x).reset_index(name='value').rename(columns={'index': 'country'})
    data['angle'] = data['value']/data['value'].sum() * 2*pi
    data['color'] = palettes

    p = figure(height=350, title= savepath, toolbar_location=None,
            tools="hover", tooltips="@country: @value", x_range=(-0.5, 1.0))

    p.wedge(x=0, y=1, radius=0.4,
            start_angle=cumsum('angle', include_zero=True), end_angle=cumsum('angle'),
            line_color="white", fill_color='color', legend_field='country', source=data)

    p.axis.axis_label = None
    p.axis.visible = False
    p.grid.grid_line_color = None

    output_file(filename=savepath, title="Static HTML file")
    save(p)


path_save_html = "D:/LEARN/LEARN/DATN/02_resources/visualize/html/"
list_tag = []

match_tag_sorted= dict(sorted(match_tag.items(), key=lambda item: item[1]))
print(match_tag_sorted)
#for tag in match_tag.keys():
#    list_tag += match_tag[tag]*[tag]
#visualize_pie_chart(list_tag, path_save_html + "list_tag.html", num=15 , palettes= viridis(16))

print(len(match_big_tag))

list_choose_index = []
for tag in match_big_tag.keys():
    list_choose_index.append(INDEX_DIC_MITRE_LEVEL2_VECTOR[tag])
list_choose_index.sort()
print(list_choose_index)

def visualize_column(list_info = [], counts = [] , savepath = "D:/visualize/visualize_format.html", num = 10, palettes = magma(10) ):
    source = ColumnDataSource(data=dict(fruits=list_info, counts=counts))

    p = figure(x_range=list_info, height=800, toolbar_location=None, title="Fruit Counts", width = 1000)
    p.vbar(x='fruits', top='counts', width=0.9, source=source, legend_field="fruits",
        line_color='white', fill_color=factor_cmap('fruits', palette=palettes, factors=list_info))

    p.xgrid.grid_line_color = None
    p.y_range.start = 0
    p.y_range.end = 18000
    p.legend.orientation = "vertical"
    p.legend.location = "top_right"
    #p.legend.visible = False


    output_file(filename=savepath, title="Static HTML file")
    save(p)

# 2. Visualize format
list_tags = []
count_tags = []
for tag in match_big_tag_.keys():
    list_tags.append(tag)
    count_tags.append(match_big_tag_[tag])


path_save_html = "D:/LEARN/LEARN/DATN/02_resources/visualize/html/"
visualize_column(list_tags, count_tags, path_save_html + "column_list_tags.html", num=15 , palettes= viridis(len(list_tags)))