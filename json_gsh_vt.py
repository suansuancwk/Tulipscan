import json


# 提取json数据
class JSON_TQ:

    def __init__(self):
        pass

    # 提取json数据
    def json_tq(self, wj):
        # 初始化
        try:
            with open(wj, 'r', encoding='gbk') as fp:
                json_data = json.load(fp)
                fp.close()
        except:
            with open(wj, 'r', encoding='utf8') as fp:
                json_data = json.load(fp)
                fp.close()
        # 查杀率:
        mc = json_data['data']['attributes']['names'][0]
        try:
            vt_cs_bd = json_data['data']['attributes']['last_analysis_stats']['malicious']  # 46个检测为病毒
        except:
            vt_cs_bd = None
        try:
            vt_cs_fbd = json_data['data']['attributes']['last_analysis_stats']['undetected']  # 24个检测非病毒
        except:
            vt_cs_fbd = None
        try:
            vt_cs_bzc = json_data['data']['attributes']['last_analysis_stats']['type-unsupported']  # 4个不支持该检测
        except:
            vt_cs_bzc = None
        try:
            vt_cs_bq = json_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']  # 家族
        except:
            vt_cs_bq=None
        try:
            vt_cs_dll = self.dll_tq(json_data)  # 获取调用的dll
            vt_cs_dll = str(vt_cs_dll)
        except:
            vt_cs_dll = None
        test = '''                                                            <<静态分析结果>>
文件:{mc}
测试为病毒个数:{vt_cs_bd}
测试非病毒个数:{vt_cs_fbd}
不支持测试结果个数:{vt_cs_bzc}
木马家族:{vt_cs_bq}
使用的dll:{vt_cs_dll}
其他详细信息请查看html测试文档!!!
        '''.format(mc=mc, vt_cs_bd=vt_cs_bd, vt_cs_fbd=vt_cs_fbd, vt_cs_bzc=vt_cs_bzc, vt_cs_bq=vt_cs_bq,
                   vt_cs_dll=vt_cs_dll)
        if vt_cs_bq is None:
            print('\033[1;32m' + test + '\033[0m')
        else:
            print('\033[1;31m' + test + '\033[0m')
        return test

    def dll_tq(self, json_data):
        dll_list = []
        lisyt = json_data['data']['attributes']['pe_info']['import_list']
        for lis in lisyt:
            dll_list.append(lis['library_name'])
        return dll_list


# if __name__ == '__main__':
#     cs = JSON_TQ()
#     cs.json_tq('./vt/Server.exe.json')
