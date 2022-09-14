
import os
import yara
import json
import string
import urllib.parse
from colorama import init, Fore

class Webshell:
    def __init__(self):
        try:
            with open('./config/path.json', 'r', encoding='gbk') as fp:
                json_data = json.load(fp)
                fp.close()
        except:
            with open('./config/path.json', 'r', encoding='utf8') as fp:
                json_data = json.load(fp)
                fp.close()
        self.webshell_gz_php = json_data["webshell_gz_php"]
        self.webshell_gz_qt = json_data['webshell_gz_qt']
        self.webshell_lj = json_data['webshell_lj']

    def fx1(self):
        q = 0
        p = 0
        jg = []
        yb = []
        rules_php = yara.compile(filepath=self.webshell_gz_php, includes=True)  # 载入yara规则
        wj = os.listdir(self.webshell_lj)
        for i in wj:
            mc_tst=i
            if '\u4e00' <= i <= '\u9fff':
                a = urllib.parse.quote(i, safe=string.printable)
                test_mc=self.webshell_lj + '/' + str(i)
                test_mv=self.webshell_lj + '/' + str(a)
                os.rename(test_mc,test_mv)
                i=a
            matches = rules_php.match(self.webshell_lj + '/' + str(i))
            a_test=mc_tst
            os.rename(self.webshell_lj + '/' + str(i),self.webshell_lj + '/' + str(a_test))
            i=mc_tst
            if len(matches) > 0:
                text = '匹配到敏感文件:' + i + '\n'
                print('\033[1;31m' + text + '\033[0m')
                jg.append(text)
                yb.append(i)
                p = p + 1
            q = q + 1
        print(Fore.BLUE + "总共扫描" + str(q) + '个文件' + ',' + '扫描出' + str(p) + '个敏感文件')
        return jg, yb

    def fx2(self):
        q = 0
        p = 0
        jg = []
        yb = []
        rules_php = yara.compile(filepath=self.webshell_gz_qt, includes=True)  # 载入yara规则
        wj = os.listdir(self.webshell_lj)
        for i in wj:
            mc_tst = i
            if '\u4e00' <= i <= '\u9fff':
                a = urllib.parse.quote(i, safe=string.printable)
                test_mc = self.webshell_lj + '/' + str(i)
                test_mv = self.webshell_lj + '/' + str(a)
                os.rename(test_mc, test_mv)
                i = a
            matches = rules_php.match(self.webshell_lj + '/' + str(i))
            a_test = mc_tst
            os.rename(self.webshell_lj + '/' + str(i), self.webshell_lj + '/' + str(a_test))
            i = mc_tst
            if len(matches) > 0:
                text = '匹配到敏感文件:' + i + '\n'
                print('\033[1;31m' + text + '\033[0m')
                jg.append(text)
                yb.append(i)
                p = p + 1
            q = q + 1
        print(Fore.BLUE + "总共扫描" + str(q) + '个文件' + ',' + '扫描出' + str(p) + '个敏感文件')
        return jg, yb




# if __name__ == '__main__':
#     cs=Webshell()
#     cs.fx2()