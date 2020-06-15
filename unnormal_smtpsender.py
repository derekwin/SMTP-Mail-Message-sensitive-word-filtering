import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart #附件
from email.header import Header, make_header

#网易邮箱为例
#设置发送代理服务器地址，登录的用户名密码，密码使用授权码
email_server=''        #用别的邮箱 换别的服务器
email_user=''   ##此处填写你的测试邮箱
email_user_passwd=''  #登陆密码，126邮箱使用授权码登录

#设置收件人（list，可以设置多人，建议一个人），sub邮件主题，msg设置邮件内容
send_to=['']  #收件人邮箱
sub='4月交易汇报'  #主题

#text正文
msg='4月份梦幻新区的订单发布数量为1000单，成交495笔，环比3月份(500单)发布单数量上升100%和成交量笔数(450)上升10%，发布单数与交笔数的增长比率严重不符。\n ' \
    '    注：附件一为梦幻4月份新区的交易明细' \
    '长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试' \
    '长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试' \
    '长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试长邮件测试'
#html正文
#html=''

#添加附件，附件信息，第一行文件名填写文件的相对目录，最后一行的文件名填写发送中显示的邮件名字
att1 = MIMEText(open('交易明细.xls', 'rb').read(), 'base64', 'utf-8') #可以是任意文件
att1["Content-Type"] = 'application/octet-stream'
# ####，正常邮件不支持中文附件名字  必须进行下面的处理
att1["Content-Disposition"] = 'attachment;filename= "%s"' % make_header([('交易明细.xls', 'UTF-8')]).encode('UTF-8')

att2 = MIMEText(open('邮件内容.doc', 'rb').read(), 'base64', 'utf-8') #可以是任意文件
att2["Content-Type"] = 'application/octet-stream'
# ####，正常邮件不支持中文附件名字  必须进行下面的处理
att2["Content-Disposition"] = 'attachment;filename= "%s"' % make_header([('邮件内容.doc', 'UTF-8')]).encode('UTF-8')

def send_email(send_to,sub,msg):
    message = MIMEMultipart()   #初始化email类
    msg_text=MIMEText(msg,'plain','utf-8') #如果发送的是html邮件，此处'plain'->'html'
    #msg_html = MIMEText(msg, 'html', 'utf-8')  #html可选项,没有做针对性解析，平常邮件很少发html这种形式的
    message.attach(msg_text)    #添加正文
    message.attach(att1)    #添加附件
    message.attach(att2)
    message['Subject']=Header(sub,'utf-8')
    message['From']=email_user
    message['To']=';'.join(send_to)

    try:
        s=smtplib.SMTP()
        s.connect(email_server)     #连接代理服务器
        print('connect done')
        s.login(email_user,email_user_passwd)   #登录
        print('login successd')
        s.sendmail(email_user,send_to,message.as_string())      #发送邮件
        s.close()
        print("成功发送！")
    except smtplib.SMTPException:
        print('ERROR,发送失败')

if __name__=='__main__':
    send_email(send_to,sub,msg)


