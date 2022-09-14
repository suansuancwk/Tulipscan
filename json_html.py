from json2html import *
import json
import os

class HTMLCS:

    def sc(self, mc):
        try:
            dict_str = open(mc, 'r', encoding='gbk').read()
        except:
            dict_str = open(mc, 'r', encoding='utf8').read()
        try:
            data_dict = json.loads(dict_str)
            data_xml = json2html.convert(data_dict)
        except:
            data_xml=None
        mc = mc.replace('./wb/', '').split('.')[0]
        html_head = r'''<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>{mc}样本报告</title>
        </head>
        <body background="./test.jpg">
        <b><font color="red">{data_xml}</font></b>
        </body>
        </html>'''
        result_html = html_head.format(mc=mc,data_xml=data_xml)
        yb = './html/' + mc + '.html'
        try:
            with open(yb, 'w', encoding='utf-8') as file:
                file.write(result_html)
                file.close()
        except:
            with open(yb, 'w', encoding='gbk') as file:
                file.write(result_html)
                file.close()
        print('\033[1;35m' + mc + '>>报告生成完毕!!!' + '\033[0m')

    def api(self, mc):
        self.sc(mc)


if __name__ == '__main__':
    cs = HTMLCS()
    wj_list = os.listdir('./wb')
    for ls in wj_list:
        wjm = './wb' + '/' + ls
        cs.sc(wjm)
