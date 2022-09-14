import time
import json_gsh_vt
import wb
import DS
import vt
import yara_test
import webshell_jc
import os
import qq_mail
import htmlxr
import ip_scan
import ip_html
# 初始化logo
logo = ''' 
 /$$$$$$$$        /$$ /$$                                                  
|__  $$__/       | $$|__/                                                  
   | $$ /$$   /$$| $$ /$$  /$$$$$$   /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$ 
   | $$| $$  | $$| $$| $$ /$$__  $$ /$$_____/ /$$_____/ |____  $$| $$__  $$
   | $$| $$  | $$| $$| $$| $$  \ $$|  $$$$$$ | $$        /$$$$$$$| $$  \ $$
   | $$| $$  | $$| $$| $$| $$  | $$ \____  $$| $$       /$$__  $$| $$  | $$
   | $$|  $$$$$$/| $$| $$| $$$$$$$/ /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$
   |__/ \______/ |__/|__/| $$____/ |_______/  \_______/ \_______/|__/  |__/
                         | $$                                              
                         | $$                                              
                         |__/                                              

使用说明：
a:进行静态扫描
b:云扫描生成测试文档
c:webshell扫描
d:扫描与主机建立连接的ip
'''

# 需要发送给谁,填写邮箱地址
msg_to = ['']
mail_yj = qq_mail.Mail()
print('\033[1;36m' + logo + '\033[0m')

# 程序开始
xz = input('请选择a或者b或者c或者d>>')
if xz == 'a':
    print('\033[1;35m' + '静态扫描开始' + '\033[0m')
    ya = yara_test.Matching()
    test = ya.run()
    fs_text = str(test) + '\n' + '详细内容请查看报告/jintaiscan/bd.txt'
    for i in msg_to:
        mail_yj.send_email('静态文件扫描报告', i, fs_text, )
    print('发送完成!!!')
    print('\033[1;35m' + '生成报告文件/jintaiscan/bd.txt' + '\033[0m')
elif xz == 'b':
    print('\033[1;35m' + '基于云扫描，时间可能会较长，生成html分析文件。' + '\033[0m')
    # 初始化
    filenames = os.listdir(r'./yangben')
    vt_url = []
    wb_url = []
    ds_url = []
    fs_textls = []
    # 首先将文件全部上传
    vtsc = vt.VTscan()
    wbsc = wb.WB()
    dssc = DS.DSY()
    for wj1 in filenames:
        try:
            wj = './yangben/' + wj1
            vt_lj = vtsc.vt_upload(wj)
            wb_lj = wbsc.wb_tjwj(wj1)
            ds_lj = dssc.ds_upload(wj)
            vt_url.append(vt_lj)
            wb_url.append(wb_lj)
            ds_url.append(ds_lj)
            time.sleep(3)
        except:
            print('网络异常')
    print('\033[1;35m' + '文件已经全部上传完成!!!' + '\033[0m')
    time.sleep(300)
    for vt_ul in vt_url:
        jsonjs = vtsc.vt_sjcl(vt_ul)
        vtsc.json_cun(jsonjs, jsonjs['data']['attributes']['names'][0])
    for wb_ul in wb_url:
        try:
            jsonsj1 = wbsc.wb_wjxy(wb_ul)
            wbsc.json_cunxy(jsonsj1, jsonsj1['data']['summary']['file_name'])
            time.sleep(2)
            # jsonsj2 = wbsc.wb_hqbg(wb_ul)
            # wbsc.json_cunfbd(jsonsj2, jsonsj1['data']['summary']['file_name'])
        except:
            print('网络异常')
    jsonjx = json_gsh_vt.JSON_TQ()
    vt_filenames = os.listdir(r'./vt')
    for wj2 in vt_filenames:
        wj3 = './vt/' + wj2
        fs_text = jsonjx.json_tq(wj3)
        fs_textls.append(str(fs_text) + '\n')
    fsnr = '扫描基本信息如下：' + '\n' + str(fs_textls)
    # for ms in msg_to:
    #     mail_yj.send_email('动态扫描报告', ms, fsnr.replace(' ',''))
    wj_list = os.listdir('./vt')
    for ls in wj_list:
        wjm = './vt' + '/' + ls
        html_sc = htmlxr.HTMLXR()
        html_sc.xr(wjm)
    html_filenames = os.listdir(r'./html')
    for html_fs in html_filenames:
        wjh = './html/' + html_fs
        if '.png' in wjh:
            continue
        else:
            try:
                f = open(wjh, "r", encoding='utf-8')
                html = f.read()
                f.close()
            except:
                f = open(wjh, "r", encoding='gbk')
                html = f.read()
                f.close()
            for ms in msg_to:
                mail_yj.send_email('动态扫描报告', ms, html)

    print('\033[1;35m' + '请查看报告!!!' + '\033[0m')
elif xz == 'c':
    shell_jc = webshell_jc.Webshell()
    print('\033[1;42m' + '检测引擎一php:' + '\033[0m')
    test1 = shell_jc.fx1()[0]
    print('\n')
    print('\033[1;42m' + '检测引擎二jsp&asp:' + '\033[0m')
    text2 = shell_jc.fx2()[0]
    fsnr = 'php引擎扫描结果:' + '\n' + str(test1) + '\n' + 'jsp&asp引擎扫描结果' + '\n' + str(text2)
    for ms in msg_to:
        mail_yj.send_email('webshell静态扫描报告', ms, fsnr)
elif xz == 'd':
    print('\033[1;36m' + '正在扫描，请稍等!!!' + '\033[0m')
    app1 = ip_scan.IPscan()
    app2 = ip_html.IP_HT()
    text=app1.hq_ip()
    app2.mb(app2.bl(text))
