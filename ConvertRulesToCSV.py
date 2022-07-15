import csv
import json
import os 
root_dir = os.path.dirname(os.path.abspath(__file__))
files = [name for name in os.listdir(root_dir) if not os.path.isfile(os.path.join(root_dir, name))]
for f_name in files:
    file = os.path.join(root_dir, f_name)
    os.chdir(file)
    file = os.getcwd()
# def ignore_files(dir, file_name):
#     return [f for f in file_name if os.path.isfile(os.path.join(dir, f))]
# result_dir=os.path.join(root_dir, r'results')
# shutil.copytree(root_dir,result_dir,ignore=ignore_files)
    RULES_JSON_FILE = 'result.json' # Elastic alerts JSON dump
    CSV_FILENAME = "Rules.csv"     # Output file

    datalist = []
    file = os.getcwd()
    print (file)
    with open(RULES_JSON_FILE) as fp:
        for data in fp.readlines():
            datalist.append(json.loads(data, strict=False))

        # for data in datalist:
            # print('\n########## Total no of rules: {} ##########'.format(len(data['rules'])))
        with open(CSV_FILENAME, "a") as fp:
            writer = csv.writer(fp)
            headers = ["Name", "Description", "Query", "Severity", "Reference", "Tactic", "ID", "Technique"]  # CSV headers
            writer.writerow(headers)  # Write the headers
            for data in datalist:
                each_rule = data['rule']
                name = each_rule['name']
                references = each_rule.get('references')
                refer = ''
                if references:
                    for each_reference in references:
                        refer = refer + '\n' + each_reference
                refer = refer.strip('\n')
                description = each_rule.get('description')
                severity = each_rule.get('severity')
                query = each_rule.get('query')

                attack_tactic = ''
                attack_tag = ''
                attack_id = ''

                # Each rule may have multiple ATT&CK info associated with it.
                # So we need no merge them.
                if each_rule.get('threat'):
                    for i, each_threat in enumerate(each_rule['threat']):
                        attack_tactic = attack_tactic + ',' + each_rule['threat'][i]['tactic']['name']
                        
                        # In addition, we need to merge sub-techniques too if present
                        if each_rule['threat'][i].get('technique'):
                            attack_tag = attack_tag + ',' + each_rule['threat'][i]['technique'][0]['name']
                            attack_id = attack_id + ',' + each_rule['threat'][i]['technique'][0]['id']

                            if each_rule['threat'][i]['technique'][0].get('subtechnique') is not None: # Check sub-tech presence
                                sub_tag_id = each_rule['threat'][i]['technique'][0]['subtechnique'][0].get('id')
                                sub_tag = each_rule['threat'][i]['technique'][0]['subtechnique'][0].get('name')
                                attack_id = attack_id + ',' + sub_tag_id
                                attack_tag = attack_tag + ',' + sub_tag

                        # Strip starting commas
                        attack_tactic = attack_tactic.lstrip(',')
                        attack_tag = attack_tag.lstrip(',')
                        attack_id = attack_id.lstrip(',')

                writer.writerow([name, description, query, severity, refer, attack_tactic, attack_id, attack_tag])
