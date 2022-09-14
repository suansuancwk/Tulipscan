
from jinja2 import Template, FileSystemLoader, Environment
import json

import json_html


class HTMLXR:

    def xr(self,mc):
        try:
            with open(mc, 'r', encoding='gbk') as fp:
                json_data = json.load(fp)
                fp.close()
        except:
            with open(mc, 'r', encoding='utf8') as fp:
                json_data = json.load(fp)
                fp.close()
        # ./vt/cmd.exe.json
        mc = mc.replace('./vt/', '').split('.json')[0]
        name = json_data['data']['attributes']['names'][0]
        anquan = int(json_data['data']['attributes']['last_analysis_stats']['undetected'])
        baodu = int(json_data['data']['attributes']['last_analysis_stats']['malicious'])
        sha256 = json_data['data']['attributes']['sha256']
        weijiance = int(json_data['data']['attributes']['last_analysis_stats']['type-unsupported'])
        try:
            muma = json_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']  # 家族
        except:
            muma = None
        try:
            names = json_data['data']['attributes']['names']
            names = str(names).replace('[', '').replace(']', '').replace("'", '').replace(',', '<br>')
        except:
            names = None
        try:
            trid = str(json_data['data']['attributes']['trid']).replace('},', '<br>').replace('[', '').replace(']',
                                                                                                               '').replace(
                '{', '').replace("'", '')
        except:
            trid = None
        try:
            signature_info = str(json_data['data']['attributes']['signature_info']).replace('{', '').replace("',",
                                                                                                             '<br>').replace(
                "': [", '<br>').replace("},", '<br>').replace('}],', '<br>').replace("'", '')
        except:
            signature_info = None
        try:
            category = str(
                json_data['data']['attributes']['popular_threat_classification']['popular_threat_category']).replace(
                '[{', '').replace('},', '<br>').replace('{', '').replace('}]', '').replace("'", '')
        except:
            category = None
        try:
            threat_name = str(
                json_data['data']['attributes']['popular_threat_classification']['popular_threat_name']).replace('[{',
                                                                                                                 '').replace(
                '},', '<br>').replace('{', '').replace('}]', '').replace("'", '')
        except:
            threat_name = None
        try:
            lang = str(json_data['data']['attributes']['pe_info']['resource_details']).replace("},", '<hr />').replace(
                ',', '<br>').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace("'", '')
        except:
            lang = None
        try:
            dll = str(json_data['data']['attributes']['pe_info']['import_list']).replace(']},', '<hr />').replace(',',
                                                                                                                  '<br>').replace(
                '[', '').replace('{', '').replace(']', '').replace('}', '').replace("'", '')
        except:
            dll = None
        try:
            av = str(json_data['data']['attributes']['last_analysis_results']).replace('},', '<hr />').replace(',',
                                                                                                               '<br>').replace(
                "{'", '<br>').replace("'", '').replace('}', '')
        except:
            av = None
        # 首先告诉Jinja2模块，jinja模板文件路径在哪？(如当前目录)
        j2_loader = FileSystemLoader('./')

        # 然后定义一个环境，告诉jinja2，从哪里调用模板
        env = Environment(loader=j2_loader)

        # 之后通过 get_template 获取并载入模板
        j2_tmpl = env.get_template('./test.html')

        # 最后传入参数，渲染模板
        result = j2_tmpl.render(name=name, anquan=anquan, baodu=baodu, weijiance=weijiance, sha256=sha256, muma=muma,
                                names=names,
                                trid=trid, signature_info=signature_info, category=category, threat_name=threat_name,
                                lang=lang, dll=dll, av=av)
        yb = './html/' + mc + '.html'
        try:
            with open(yb, 'w', encoding='utf-8') as file:
                file.write(result)
                file.close()
        except:
            with open(yb, 'w', encoding='gbk') as file:
                file.write(result)
                file.close()
        print('\033[1;35m' + mc + '>>报告生成完毕!!!' + '\033[0m')

# app = HTMLXR()
# wj_list = os.listdir('./vt')
# for ls in wj_list:
#     wjm = './vt' + '/' + ls   # ./vt/cmd.exe.json
#     app.xr(wjm)