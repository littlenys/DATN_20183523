import requests
import re
import ujson
import js2py
import multiprocessing as mp

from pathlib import Path
from bs4 import BeautifulSoup, SoupStrainer

def get_techique_type(num):
	technique = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Command and Control', 'Network Effects', 'Remote Service Effects', 'Impact']
	return technique[num]

class ProcessTree:
	def __init__(self, process_str="ROOT", level=-1):
		self.process_str = process_str
		self.process_tree = []
		self.level = level
		pass

	def AppendToTree(self, node):
		self.process_tree.append(node)

	def Parse_process_tree(self, soup, new_soup):
		siblings = new_soup.find_all("ul", recursive=False)

		json_tree = {}
		for each_sibling in siblings:
			temp_json = {}
			if "cleanup" in each_sibling.li.text or "System is" in each_sibling.li.text:
				continue
			new_process_tree = ProcessTree(each_sibling.li.text, level=self.level+1)
			PID = re.search(r'PID: (\d+)', each_sibling.li.text).group(1)
			cmdline = re.search(r'cmdline: (.*) MD5', each_sibling.li.text).group(1)
			MD5 = re.search(r'MD5: ([A-F0-9]{32})', each_sibling.li.text).group(1)
			temp_json['PID'] = PID
			temp_json['cmdline'] = cmdline
			temp_json['MD5'] = MD5

			element = soup.find('div', {'id': f'{PID + MD5}'})
			next_element = element.next_sibling
			process_tag = next_element['id']
			child_tree = new_process_tree.Parse_process_tree(soup, each_sibling)
			temp_json['child'] = child_tree
			json_tree[process_tag] = temp_json

		return json_tree

p = Path(r'D:\output.txt')
def worker(pos):
    final_url = f'https://www.joesandbox.com/analysis/{pos}/0/html?download=1'
    r = requests.get(final_url)
    file_data = r.text

    # ================ Read the behavior from the javascript ===================
    re.compile(r'^behavior=(.*);(?=//end)', flags=re.DOTALL)
    

    # ================ Parse the HTML file ================
    startup = SoupStrainer('div', {'id': ['staticFileInfo', 'behavior-collapsable', 'startup1', 'mitreAttackMatrix', 'generalInformationOverview', re.compile(r"techniqueT\d+")]})
    html_soup = BeautifulSoup(file_data, 'lxml', parse_only=startup)
    signature_strainer = SoupStrainer('div', class_='signature-expert-wrapper')
    signature_soup = BeautifulSoup(file_data, 'lxml', parse_only=signature_strainer)

    # ===================== Parse the process tree ==================
    new_soup = html_soup.find('div', {'id': 'startup1'}).div
    process_tree = ProcessTree()
    json_tree = process_tree.Parse_process_tree(html_soup, new_soup)
    

    # =================== Find the classification ===============
    gen_info = html_soup.find("div", {"id": "generalInformationOverview"})
    malware_type = ""
    
    try:
        pos = gen_info.find("td", text=re.compile(r"mal\d+[\.@]"))
        malware_type = pos.text.split('@')[0]
    except:
        malware_type = "Clean"
        
    if malware_type == "Clean":
        return
    
    sys = malware_type.split('.')[-1]
    if 'win' not in sys:
        return
        
    mal_hash = html_soup.find(text=re.compile(r'^[a-f0-9]{64}$'))
    if mal_hash == None:
        return

    # ============ Parse Signature =============================
    signature_element = signature_soup.find('table', class_='table signatureTable bd')

    # if it is the begininning of signature
    signature_table = {}
    signature_part = ''
    while signature_element != None:
        signature = {}
        if all(x in signature_element['class'] for x in ['table', 'signatureTable', 'bd']):
            signature_part = signature_element.text
            signature_element = signature_element.next_sibling
            continue

        signature['signature_header'] = signature_part
        if 'signature-jump' in signature_element['class']:
            signature_name = signature_element.text

            # Get the behavior
            signature_element = signature_element.next_sibling
            behavior_signature = signature_element.find('a', class_='behaviorJump')
            if behavior_signature == None:
                signature_element = signature_element.next_sibling
                continue
            
            signature['behavior_id'] = behavior_signature['data-id']
            signature['pid_md5'] = behavior_signature['data-pidmd5']
            signature['data_section'] = behavior_signature['data-section']
            signature['data_activity'] = behavior_signature['data-activity']

            signature_table[signature_name] = signature

        signature_element = signature_element.next_sibling


    # ======= Parse Mitre ATT&CK =================
    mitre = html_soup.find("div", {"id": "mitreAttackMatrix"})
    mitre_headers = mitre.find('tr', class_='mitreattack-head').find_all('th')

    table_header = []
    for each_header in mitre_headers:
        table_header.append(each_header.text)
        pass

    mitre_body = mitre.find('tbody').find_all('tr')
    mitre_table = {}
    for each_body in mitre_body:
        for k, each_table_element in enumerate(each_body.find_all('td')):
            mitre_data = {}
            mitre_data['techinque_type'] = table_header[k]
            if each_table_element.has_attr('class'):
                technique_id = each_table_element.find('span', href=True)['href'][1:]
                # if the attribute is mark on mitre table
                signature = html_soup.find("div", class_="modal hide fade", id=technique_id).find("div", class_="modal-body").find_all("p")
                mitre_data['signature_len'] = len(signature)
                mitre_data['signatures'] = [x.text for x in signature]
                mitre_table[each_table_element.text.lstrip('0123456789.- ')] = mitre_data
                continue

            # the atribute doesn't get mark on mitre table
            mitre_data['signature_len'] = 0
            mitre_data['signatures'] = []
            mitre_table[each_table_element.text.lstrip('0123456789.- ')] = mitre_data				

    # ===================== Parse behavior =================
    re_behavior = re.compile(r'\nbehavior=([\s\S]*)(?=;\/\/end)', flags=re.MULTILINE)
    matchValue = re.search(re_behavior, file_data)
    js = """
    behavior="""+ f"{matchValue.group(1)}" + """;
    function a() {
        return JSON.stringify(behavior)
    }
    a()
    """
    json_behavior = ujson.loads(js2py.eval_js(js))

    # ============= Save into file ===================
    p = Path('E:\\Dai hoc bk\\crawl_data')
    p.mkdir(parents=True, exist_ok=True)
    mitre_path = p / "mitre_data_new"
    mitre_path.mkdir(exist_ok=True)

    # open file
    mitre_json = mitre_path / f"{malware_type}-{mal_hash}-mitre.json"
    mitre_json.touch(exist_ok=True)
    behavior_json = mitre_path / f"{malware_type}-{mal_hash}-behavior.json"
    behavior_json.touch(exist_ok=True)
    signature_json = mitre_path / f"{malware_type}-{mal_hash}-signature.json"
    signature_json.touch(exist_ok=True)
    process_tree_json = mitre_path / f"{malware_type}-{mal_hash}-processTree.json"
    process_tree_json.touch(exist_ok=True)


    # save json to each file
    with mitre_json.open('w') as outfile:
        ujson.dump(mitre_table, outfile)

    with behavior_json.open('w') as outfile:
        ujson.dump(json_behavior, outfile)

    with signature_json.open('w') as outfile:
        ujson.dump(signature_table, outfile)

    with process_tree_json.open('w') as outfile:
        ujson.dump(json_tree, outfile)


    print(f'{mal_hash}: DONE')
    
if __name__ == '__main__':
	first_pos = 626865
	pool = mp.Pool(processes=6)
	pool.imap_unordered(worker, range(first_pos, first_pos - 200000, -1))
	pool.close()
	pool.join()
	pass