import json
import requests
import os


class DSY:

    def __init__(self):
        with open('./config/config.json', 'r', encoding='utf8') as fp:
            json_data = json.load(fp)
        self.client_id = json_data['ds_client_id']
        self.client_secret = json_data['ds_client_secret']
        self.access_token = self.ds_token()['access_token']
        self.path_wj='./yangben'

    # 獲取access_token
    def ds_token(self):
        url = 'https://sandbox.riskivy.com/openapi/oauth/token'
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials',
            'scope': 'openapi'
        }
        yz = requests.post(url=url, data=data).text
        return json.loads(yz)

    # 文件上傳,獲取sha1
    def ds_upload(self, wj):
        url = 'https://sandbox.riskivy.com/openapi/mac/sample/upload'
        data = {
            'access_token': self.access_token
        }
        files = {"file": open(wj, "rb")}
        sha1_txt = requests.post(url=url, files=files, data=data).json()
        sha1 = sha1_txt['data']['sha1']
        return sha1

    # 獲取報告
    def ds_jghq(self, sha1):
        url = 'https://sandbox.riskivy.com/openapi/mac/sample/report/%s' % sha1
        data = {
            'access_token': self.access_token
        }
        js = requests.get(url=url, params=data).json()
        return js

    # 報告保存
    def json_cunxy(self, jsonsj, wj):
        wjm = './ds/' + wj + 'credit' + '.json'
        with open(wjm, 'w', encoding='gbk') as write_f:
            write_f.write(json.dumps(jsonsj, indent=4, ensure_ascii=False))
            write_f.close()

    # 運行主程序
    def run(self):
        sha=[]
        filenames = os.listdir(self.path_wj)
        for wj in filenames:
            wj = self.path_wj+'/' + wj
            sha1=self.ds_upload(wj)
            sha.append(sha1)
        for s in sha:
            wb=self.ds_jghq(s)
            self.json_cunxy(wb,'server.exe')

    # 程序api
    def ds_api(self):
        self.run()

# if __name__ == '__main__':
#     cs=DSY()
#     cs.ds_api()
