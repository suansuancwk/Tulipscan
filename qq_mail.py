import smtplib
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

class Mail:
    def __init__(self):
        self.msg_from = '' # qq邮箱
        self.passwd = '' # qq邮箱密钥
    # 写成了一个通用的函数接口，想直接用的话，把参数的注释去掉就好
    def send_email(self, topic, msg_to, text_content, file_path=None):
        global s
        msg = MIMEMultipart()
        subject = topic  # 主题
        text = MIMEText(text_content,'html', 'utf-8')  # 文件内容
        msg.attach(text)
        # docFile = 'C:/Users/main.py'  如果需要添加附件，就给定路径
        if file_path:  # 最开始的函数参数我默认设置了None ，想添加附件，自行更改一下就好
            docFile = file_path  # 附件
            docApart = MIMEApplication(open(docFile, 'rb').read())
            docApart.add_header('Content-Disposition', 'attachment', filename=docFile)
            msg.attach(docApart)
            print('附件发送成功！')
        msg['Subject'] = subject
        msg['From'] = self.msg_from
        msg['To'] = msg_to
        try:
            s = smtplib.SMTP_SSL("smtp.qq.com", 465)
            s.login(self.msg_from, self.passwd)
            s.sendmail(self.msg_from, msg_to, msg.as_string())
            print('\033[1;35m' + "邮件发送成功" + '\033[0m')
        except smtplib.SMTPException as e:
            print("邮件发送失败")
        finally:
            s.quit()


