import os
import yara
import json

from colorama import Fore


def findAllFile(base):
    for root, ds, fs in os.walk(base):
        for f in fs:
            yield f


def bianli(path):
    wj = []
    for i in findAllFile(path):
        wj.append(i)
    return wj


jg = []
yb = []
q = 0
p = 0
with open('./config/path.json', 'r', encoding='utf8') as fp:
    json_data = json.load(fp)
    fp.close()
path_gz = json_data["path_gz"]  # ./webshellgz/index.yar
path_yb = json_data['path_yb']  # ./yangben
rules = yara.compile(filepath=path_gz, includes=True)  # 规则路径
wj = bianli(path_yb)
for i in wj:
    matches = rules.match(path_yb + '/' + str(i))  # 进行匹配
    if len(matches) > 0:
        text = '匹配到敏感文件:' + i + '，规则为:' + str(matches) + '\n'
        text1 = '匹配到敏感文件:' + i
        print('\033[1;31m' + text + '\033[0m')
        jg.append(text1)
        yb.append(i)
        p = p + 1
    q = q + 1
print(Fore.BLUE + "总共扫描" + str(q) + '个文件' + ',' + '扫描出' + str(p) + '个敏感文件')
