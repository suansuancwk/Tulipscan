import requests
import json
import re



def googleTranslate(text):
    url = 'https://translate.google.cn/_/TranslateWebserverUi/data/batchexecute?rpcids=MkEWBc&f.sid=-2984828793698248690&bl=boq_translate-webserver_20201221.17_p0&hl=zh-CN&soc-app=1&soc-platform=1&soc-device=1&_reqid=5445720&rt=c'
    headers = {
        'origin': 'https://translate.google.cn',
        'referer': 'https://translate.google.cn/',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
        'x-client-data': 'CIW2yQEIpbbJAQjEtskBCKmdygEIrMfKAQj2x8oBCPfHygEItMvKAQihz8oBCNzVygEIi5nLAQjBnMsB',
        'Decoded': 'message ClientVariations {repeated int32 variation_id = [3300101, 3300133, 3300164, 3313321, 3318700, 3318774, 3318775, 3319220, 3319713, 3320540, 3329163, 3329601];}',
        'x-same-domain': '1'
    }
    data = {
        'f.req': f'[[["MkEWBc","[[\\"{text}\\",\\"auto\\",\\"zh-CN\\",true],[null]]",null,"generic"]]]'
    }

    res = requests.post(url, headers=headers, data=data).text
    pattern = '\)\]\}\'\s*\d{3,4}\s*\[(.*)\s*'
    part1 = re.findall(pattern, res)
    part1_list = json.loads('[' + part1[0])[0]
    if part1_list[2] is None:
        print(text)
        return text
    content1 = part1_list[2].replace('\n', '')
    part2_list = json.loads(content1)[1][0][0][5:][0]
    s = ''
    for i in part2_list:
        s += i[0]
        # s += i[1][1]
    print(s)
    return s


text = 'app'
googleTranslate(text)
