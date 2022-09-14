import os
import re
import time

import requests


class IPscan:
    def getip(self, str):
        result = re.findall(r'\D(?:\d{1,3}\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\D', str)
        ret_start = re.match(r'(\d{1,3}\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\D', str)
        if ret_start:
            result.append(ret_start.group())
        ret_end = re.search(r'\D(\d{1,3}\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$', str)
        if ret_end:
            result.append(ret_end.group())
        ip_list = []
        for r in result:
            ret = re.search(r'((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)', r)
            if ret:
                ip_list.append(ret.group())
        return ip_list

    def hq_ip(self):
        ips_list = []
        if 1:
            r = os.popen("netstat -nt")
            net = r.read()
            r.close()
            x = self.getip(net)
            new_li = list(set(x))
            new_li.sort(key=x.index)
            x = new_li
            for item in x:
                if "0.0.0.0" in item:
                    x.remove(item)
            for item in x:
                if "127.0.0.1" in item:
                    x.remove(item)
            for i in x:
                ips_list.append(self.ipscan(i))
            for mm in ips_list:
                if mm is None:
                    ips_list.remove(mm)
            print('\033[1;33m' + str(ips_list) + '\033[0m')
            return ips_list # [[],[],[],[]]

    def ipscan(self, ip):
        sj_list = []
        url = 'http://ip-api.com/json/' + ip + '?lang=zh-CN'
        time.sleep(0.2)
        try:
            ip_json = requests.get(url=url).json()
        except:
            print('连接超时!!')
        if ip_json['status'] == 'success':
            sj_list.append(ip_json['query'])
            sj_list.append(ip_json['country'])
            sj_list.append(ip_json['regionName'])
            try:
                jwd = str(ip_json['lat']) + ',' + str(ip_json['lon'])
            except:
                jwd = '***'
            sj_list.append(jwd)
            try:
                sj_list.append(ip_json['org'])
            except:
                sj_list.append('***')
            return sj_list
        else:
           print('\033[1;36m' + '保留地址' + '\033[0m')


# app = IPscan()
# app.ipscan('150.158.148.231')

# if __name__ == '__main__':
#     app = IPscan()
#     app.hq_ip()
