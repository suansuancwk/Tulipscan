import base64
import json
import os
import requests
import time


class VTscan:
    def __init__(self):
        with open('./config/config.json', 'r', encoding='utf8') as fp:
            json_data = json.load(fp)
        self.vt_api = json_data["vt_api"]

    # 上传样本致vt，获取样本接口链接
    def vt_upload(self, wj):
        url = "https://www.virustotal.com/api/v3/files"
        files = {"file": open(wj, "rb")}
        headers = {"x-apikey": self.vt_api}
        response = requests.post(url, files=files, headers=headers).json()
        base_url1 = response['data']['id']
        url1 = base64.b64decode(base_url1).decode('utf8').split(':')[0]
        return url1

    # 将返回的json保存到本地
    def json_cun(self, jsonsj, wj1):
        wjm = 'vt/' + wj1 + '.json'
        try:
            with open(wjm, 'w', encoding='gbk') as write_f:
                write_f.write(json.dumps(jsonsj, indent=4, ensure_ascii=False))
                write_f.close()
        except:
            with open(wjm, 'w', encoding='utf8') as write_f:
                write_f.write(json.dumps(jsonsj, indent=4, ensure_ascii=False))
                write_f.close()

    # 获取返回的数据，进行过滤处理
    def vt_sjcl(self, sha1):
        url = "https://www.virustotal.com/api/v3/files/%s" % sha1
        headers = {
            "Accept": "application/json",
            "x-apikey": self.vt_api
        }
        try:
            response = requests.get(url, headers=headers).json()
            return response
        except:
            print('网络延迟')
            return 0

    # 获取返回的行为报告
    # def vt_xwbg(self,sha1):
    #     url = "https://www.virustotal.com/api/v3/files/%s/behaviour_summary" % sha1
    #     headers = {
    #         "Accept": "application/json",
    #         "x-apikey": self.vt_api
    #     }
    #     response = requests.get(url, headers=headers, timeout=60).json()
    #     print(response)

    # 主程序運行
    def run(self):
        sha1_ls = []
        filenames = os.listdir(r'./yangben')
        for wj1 in filenames:
            wj = './yangben/' + wj1
            try:
                sha1 = self.vt_upload(wj=wj)
                sha1_ls.append(sha1)
                print('文件'+wj1+'上传成功!')
            except:
                print('文件上传失败')
            time.sleep(15)
        for s in sha1_ls:
            try:
                jsonjs = self.vt_sjcl(sha1=s)
                self.json_cun(jsonjs, jsonjs['data']['attributes']['names'][0])
            except:
                print('获取报告失败')

    # class調用
    def vt_api(self):
        self.run()

# if __name__ == '__main__':
#     y=VTscan()
#     y.run()
