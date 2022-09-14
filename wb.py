import time
import requests
import os
import json


class WB:
    # 出釋懷參數
    def __init__(self):
        with open('./config/config.json', 'r', encoding='utf8') as fp:
            json_data = json.load(fp)
        self.wb_api = json_data['wb_api']
        self.sandbox_type = json_data['sandbox_type']
        self.file_dir = './yangben'

    # 文件上傳，獲取sha256
    def wb_tjwj(self, file_name):
        url = 'https://api.threatbook.cn/v3/file/upload'
        fields = {
            'apikey': self.wb_api,
            'sandbox_type': self.sandbox_type,
            'run_time': 60
        }
        files = {
            'file': (file_name, open(os.path.join(self.file_dir, file_name), 'rb'))
        }
        try:
            response = requests.post(url, data=fields, files=files).json()
            return response['data']['sha256']
        except:
            print('请确保文件目录下存在该文件！！！程序退出！')
            return 0

    # 获取文件信誉报告
    def wb_wjxy(self, sha256):
        url = 'https://api.threatbook.cn/v3/file/report'
        params = {
            'apikey': self.wb_api,
            'sandbox_type': self.sandbox_type,
            'sha256': sha256
        }
        response = requests.get(url, params=params).json()
        return response

    # 获取文件反病毒引擎检测报告
    def wb_hqbg(self, sha256):
        url = 'https://api.threatbook.cn/v3/file/report/multiengines'
        params = {
            'apikey': self.wb_api,
            'sandbox_type': self.sandbox_type,
            'sha256': sha256
        }
        response = requests.get(url, params=params).json()
        return response

    # 信譽報告保存
    def json_cunxy(self, jsonsj, wj):
        wjm = './wb/' + wj + 'credit' + '.json'
        with open(wjm, 'w', encoding='gbk') as write_f:
            write_f.write(json.dumps(jsonsj, indent=4, ensure_ascii=False))
            write_f.close()

    # def json_cunfbd(self, jsonsj, wj):
    #     wjm = './wb/' + wj + 'virus' + '.json'
    #     with open(wjm, 'w', encoding='gbk') as write_f:
    #         write_f.write(json.dumps(jsonsj, indent=4, ensure_ascii=False))
    #         write_f.close()

    # 主程序
    def run(self):
        sha1_ls = []
        filenames = os.listdir(self.file_dir)
        for wj1 in filenames:
            sha256 = self.wb_tjwj(wj1)
            sha1_ls.append(sha256)
        time.sleep(60)
        for s in sha1_ls:
            jsonsj1=self.wb_wjxy(s)
            self.json_cunxy(jsonsj1,jsonsj1['data']['summary']['file_name'])
            time.sleep(2)
            # jsonsj2=self.wb_hqbg(s)
            # self.json_cunfbd(jsonsj2,jsonsj1['data']['summary']['file_name'])

    # api調用
    def api_wb(self):
        self.run()


