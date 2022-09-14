# -*- encoding: utf-8 -*-
import os
import yara
import json
import string
import urllib.parse
from colorama import init, Fore
from pyscreeze import unicode

init(autoreset=True)


class Matching:

    def findAllFile(self, base):
        for root, ds, fs in os.walk(base):
            for f in fs:
                yield f

    def bianli(self, path):
        wj = []
        for i in self.findAllFile(path):
            wj.append(i)
        return wj

    def xie(self, nr):
        try:
            with open('./jintaiscan/bd.txt', 'a', encoding='utf8') as f:
                f.write(nr)
                f.close()
        except:
            with open('./jintaiscan/bd.txt', 'a', encoding='gbk') as f:
                f.write(nr)
                f.close()

    def chaxun(self):
        q = 0
        p = 0
        try:
            with open('./config/path.json', 'r', encoding='utf8') as fp:
                json_data = json.load(fp)
                fp.close()
        except:
            with open('./config/path.json', 'r', encoding='gbk') as fp:
                json_data = json.load(fp)
                fp.close()
        path_gz = json_data["path_gz"]
        path_yb = json_data['path_yb']
        jg = []
        yb = []
        rules = yara.compile(filepath=path_gz, includes=True)  # 规则路径
        wj = self.bianli(path_yb)
        for i in wj:
            mc_tst=i
            if '\u4e00' <= i <= '\u9fff':
                a = urllib.parse.quote(i, safe=string.printable)
                test_mc=path_yb + '/' + str(i)
                test_mv=path_yb + '/' + str(a)
                os.rename(test_mc,test_mv)
                i=a
            matches = rules.match(path_yb + '/' + str(i))
            a_test=mc_tst
            os.rename(path_yb + '/' + str(i),path_yb + '/' + str(a_test))
            i=mc_tst
            if len(matches) > 0:
                text = '匹配到敏感文件:' + i + '，规则为:' + str(matches) + '\n'
                text1 = '匹配到敏感文件:' + i
                print('\033[1;31m' + text + '\033[0m')
                jg.append(text1)
                yb.append(i)
                self.xie(text)
                p = p + 1
            q = q + 1
        print(Fore.BLUE + "总共扫描" + str(q) + '个文件' + ',' + '扫描出' + str(p) + '个敏感文件')
        return jg, yb

    def run(self):
        text=self.chaxun()[0]
        return text


# if __name__ == '__main__':
#     test = Matching()
#     print(test.run())
