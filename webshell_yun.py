import os
import json

from colorama import Fore


class WEBSHELL:

    def __init__(self):
        try:
            with open('./config/path.json', 'r', encoding='gbk') as fp:
                json_data = json.load(fp)
                fp.close()
        except:
            with open('./config/path.json', 'r', encoding='utf8') as fp:
                json_data = json.load(fp)
                fp.close()
        self.path = json_data["webshell_lj"]

    # 文件上传
    def wjsc(self,wjmc):
        sj = os.popen('curl https://scanner.baidu.com/enqueue -F archive=@./webshell/%s' % wjmc).read()
        for line in sj.splitlines():
            zj = json.loads(line)
            return zj['url']

    # 获取报告
    def hqbg(self,url):
        jc_bg=[]
        jg = os.popen('curl %s' % url).read()
        for line in jg.splitlines():
            zj = json.loads(line)[0]
            jc_jg=zj['data'][0]['descr']
            if jc_jg is None:
                pass
            else:
                jc_bg.append(jc_jg)



if __name__ == '__main__':
    url=[]
    cs=WEBSHELL()
    filenames = os.listdir('./webshell')
    for shell in filenames:
        url.append(cs.wjsc(shell))
    for u in url:
        cs.hqbg(u)






