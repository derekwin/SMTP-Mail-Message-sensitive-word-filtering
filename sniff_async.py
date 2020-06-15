#coding:utf-8
from scapy.all import *
from multiprocessing import Queue,Process
import base64
import os

# 进程1入口
# 抓包，写入q_data队列
class getbuffer:
    def __init__(self,filterrule,q_data):
        self.q=q_data                            
        self.filterrule=filterrule

    def getbuffertoqueque(self,smtp):
        if Raw in smtp:
            data=str(smtp[Raw].load)[2:-1]
            if data[:12] == 'Content-Type':
                self.q.put('[loaded]')
                self.q.put(str(smtp[Raw].load)[2:-1])
            elif data[:4] == '250 ':
                self.q.put('[loaded]')
                self.q.put(str(smtp[Raw].load)[2:-1])
            else:
                self.q.put(str(smtp[Raw].load)[2:-1])
    def sniffsmtp(self):
        print("嗅探进程 -> 已启动 ")
        sniff(filter=self.filterrule, prn=self.getbuffertoqueque)

# 进程3，邮件信息处理，敏感词过滤以及存档
# 从q_file读取信息，对邮件进行过滤以及本地存档
def datafilter(q_file):
    print("敏感词过滤进程 -> 已启动")
    file_buffer=[]
    if_nomal=1
    WAF = DFAFilter()
    WAF.parseSensitiveWords('setting/keywords.txt')
    while True:
        time.sleep(1)
        print("------------\n嗅探中")
        value=q_file.get(True)
        if value=='[got one mail]':
            while True:
                mail = q_file.get(True)
                if mail == '[end one mail]':
                    gettime = time.localtime()
                    log_filename=str(gettime.tm_year) + str(gettime.tm_mon) + str(gettime.tm_mday)
                    log_time = str(gettime.tm_year)+'年'+ str(gettime.tm_mon)+'月' + str(gettime.tm_mday)+'日' + '_' + str(gettime.tm_hour)+'时' + str(gettime.tm_min) +'分'+ str(gettime.tm_sec)+'秒'
                    if if_nomal==0:
                        print(log_time+'发现《可疑数据》'+'   '+'From:'+file_buffer[0]+'--->'+'To:'+file_buffer[1] )
                        
                        if not os.path.exists('email_log/unnormal/'):
                            os.makedirs('email_log/unnormal/')
                        with open('email_log/unnormal/'+log_filename+'.txt','a+') as f:
                            f.write('\n')
                            f.write(log_time)
                            for item in file_buffer:
                                f.write('\n')
                                f.write(item)
                            f.write('\n')        
                    # 只拦截有问题的邮件            
                    # else:
                    #     print(log_time+'正常邮件'+'   '+'From:'+file_buffer[0]+'--->'+'To:'+file_buffer[1] )
                        
                    #     if not os.path.exists('email_log/normal/'):
                    #         os.makedirs('email_log/normal/')
                    #     with open('email_log/normal/'+log_filename+'.txt','a+') as f:
                    #         f.write('\n')
                    #         f.write(log_time )
                    #         for item in file_buffer:
                    #             f.write('\n')
                    #             f.write(item)
                    #         f.write('\n')
                    if_nomal=1
                    file_buffer=[]
                    break
                if not isinstance(mail,zip):
                    if WAF.filterSensitiveWords(mail) != 0:
                        if_nomal=0
                    file_buffer.append(mail)
                else:
                    for i in mail:
                        if WAF.filterSensitiveWords(i[0]) != 0:
                            if_nomal = 0
                        file_buffer.append(i[0])
                        gettime=time.localtime()
                        filename_time=str(gettime.tm_year) + str(gettime.tm_mon) + str(gettime.tm_mday)+ '_' +str(gettime.tm_hour)+str(gettime.tm_min)+str(gettime.tm_sec)
                        if not os.path.exists('email_log/file/'):
                            os.makedirs('email_log/file/')
                        with open('email_log/file/'+filename_time+'_'+i[0],'wb') as f:
                            b = base64.b64decode(i[1].encode('utf-8'))[:-2]
                            f.write(b)                                   #此处数据是byte


class DFAFilter(object):
    def __init__(self):
        super(DFAFilter, self).__init__()
        self.keyword_chains = {}
        self.delimit = '\x00'

    # 读取解析敏感词
    def parseSensitiveWords(self, path):
        ropen = open(path, 'r')
        text = ropen.read()
        keyWordList = text.split(',')
        for keyword in keyWordList:
            self.addSensitiveWords(str(keyword).strip())

    # 生成敏感词树
    def addSensitiveWords(self, keyword):
        keyword = keyword.lower()
        chars = keyword.strip()
        if not chars:
            return
        level = self.keyword_chains
        for i in range(len(chars)):
            if chars[i] in level:
                level = level[chars[i]]
            else:
                if not isinstance(level, dict):
                    break
                for j in range(i, len(chars)):
                    level[chars[j]] = {}

                    last_level, last_char = level, chars[j]

                    level = level[chars[j]]
                last_level[last_char] = {self.delimit: 0}
                break
            if i == len(chars) - 1:
                level[self.delimit] = 0

    # 过滤敏感词
    def filterSensitiveWords(self, message, repl="*"):
        message = message.lower()
        ret = []
        start = 0
        knum=0          # knum作为判据，0表示没有敏感词，1表示发现敏感词
        while start < len(message):
            level = self.keyword_chains
            step_ins = 0
            message_chars = message[start:]
            for char in message_chars:
                if char in level:
                    step_ins += 1
                    if self.delimit not in level[char]:
                        level = level[char]
                    else:               # 发现敏感词
                        ret.append(repl * step_ins)
                        start += step_ins - 1
                        knum=1      # knum置1
                        break
                else:
                    ret.append(message[start])
                    break
            start += 1
        return knum



# 进程2 数据处理管道

# 数据处理管道3，提取邮件信息，存入q_file队列
def getmetadata(q_file):
    while True:
        result=yield
        rawlist = re.findall(r"=========(.*?)--", result)
        ##匹配邮件收信息
        list1 = re.findall(r"From:(.*?)\\r\\n", rawlist[0])  # 正则读取from字段
        fromlist = ''
        for i in list1:  # findall导出的是list，存成字符串
            fromlist = fromlist + i
        ###匹配TO
        list2 = re.findall(r"To:(.*?)\\r\\n\\r\\n", rawlist[0])
        tolist = ''
        for i in list2:
            tolist = tolist + i

        ###匹配SUB
        list3 = re.findall(r"Subject: =\?utf-8\?b\?(.*)\?=\\r\\n", rawlist[0])
        sublist = ''
        for i in list3:
            sublist = sublist + i
        sublist = base64.b64decode(sublist.encode('utf-8')).decode('utf-8')

        ###匹配正文信息
        list4 = re.findall(r"Encoding: base64\\r\\n\\r\\n(.*)\\r\\n\\r\\n", rawlist[1])
        datalist = ''
        for i in list4:
            datalist = datalist + i
        # 正文是base64编码
        # 正常字符串正文可以直接解析，但是这块是list导出的字符串，将\r\n存成了\\r\\n，print却不显示
        datalist_right = ''
        slicelist = datalist.split('\\r\\n')  # 手工加入正确的\r\n
        for slice in slicelist:
            datalist_right = datalist_right + slice
        # 正常应该拼接接入\r\n 但是这块直接连起来却可以用,就这么用吧
        data1 = base64.b64decode(datalist_right.encode('utf-8')).decode('utf-8')  # 正文解码，注意python的编码问题

        ###匹配附件名字
        ##假设多个附件 遍历rawlist的[2:-1]都是附件
        namelist = []
        filelist=[]
        for k in rawlist[2:-1]:
            list5 = re.findall(r"filename= \"=\?utf-8\?b\?(.*?)\?=", k)
            for i in list5:
                namelist.append(base64.b64decode(i.encode('utf-8')).decode('utf-8'))  # 附件名解码
        ## namelist是一个附件名字列表 解密 ：base64.b64decode(datalist.encode('utf-8')).decode('utf-8')
            list6=re.findall(r"\?=\"\\r\\n\\r\\n(.*)\\r\\n\\r\\n", k)
            for i in list6:
                filelist.append(str(i).replace('\\r\\n','\r\n'))            #windows的回车\\r\\n,\r\n
        # 提取附件
        # 解码方法同正文信息，将解码后的数据以二进制写入文件，重命名成附件名字即可
        # 将提取的信息存入list
        q_file.put('[got one mail]')
        q_file.put(fromlist)
        q_file.put(tolist)
        q_file.put(sublist)
        q_file.put(data1)
        q_file.put(zip(namelist,filelist))
        q_file.put('[end one mail]')

# 数据处理管道2，获取邮件数据，对数据包组合还原成初始邮件数据包，并通过协程的方式把数据传到getmetadata
def getmail(q_file):
    metadata=getmetadata(q_file)
    next(metadata)
    result=None
    mail=''
    while True:
        value=yield result
        if value == '[loaded]':
            while True:
                inserted_value = yield
                if inserted_value[:4]=="250 ":
                    break
                if inserted_value == '[loaded]':
                    metadata.send(mail)
                    mail=''
                    break
                mail=mail + inserted_value

# 数据处理管道1，从q_data读取数据，把数据传到getmail
def get_data(q_data,q_file):
    print("数据处理进程 -> 已启动")
    test=getmail(q_file)
    next(test)
    while True:
        value=q_data.get(True)
        test.send(value)


if __name__=="__main__":
    filterrule = 'tcp port 25'
    q_data=Queue()
    q_file=Queue()
    getsmtp = getbuffer(filterrule,q_data)

    p1=Process(target=getsmtp.sniffsmtp)
    p2=Process(target=get_data,args=(q_data,q_file,))
    p3=Process(target=datafilter,args=(q_file,))

    p1.start()
    p2.start()
    p3.start()

    p1.join()
    p2.join()
    p3.join()