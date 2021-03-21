# 导入相应的模块
from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import re
from datetime import datetime
from HTMLParser import HTMLParser

class TagStripper(HTMLParser):
    def __init__(self):
        # 初始化函数
        HTMLParser.__init__(self)
        self.page_text = []
	
    # 获得标签之间的字符串
    def handle_data(self, data):
        self.page_text.append(data)
	
    # 获得页面中的注释
    def handle_comment(self, data):
        self.handle_data(data)
	
    def strip(self, html):
        # 接受一个字符串类型的html内容，进行解析
        self.feed(html)
        # 返回最后的字符串，每个字符串以空格相隔
        return " ".join(self.page_text)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        # 使用set()函数防止重复
        self.hosts = set()
		# 初始化字典集合，默认增加‘password’
        self.wordlist = set(['password'])
		# 模块命名与注册
        callbacks.setExtensionName("BHP Wordlist")
        callbacks.registerContextMenuFactory(self)

        return
	
    # 创建菜单，返回菜单列表
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Create Wordlist", actionPerformed=self.wordlist_menu))

        return menu_list
	
    # 行动函数
    def wordlist_menu(self, event):
		# 获取用户点击的详情信息
        http_traffic = self.context.getSelectedMessages()
		
        for traffic in http_traffic:
            # 获得http服务对象
            http_service = traffic.getHttpService()
            # 得到http中host属性
            host = http_service.getHost()
			# 添加到集合中
            self.hosts.add(host)
			# 获取响应信息
            http_response = traffic.getResponse()
			# 在响应信息存在的情况下使用自定义的get_words()函数获取页面信息生成字典
            if http_response:
                self.get_words(http_response)
		# 将最后的结果利用此函数回显出来
        self.display_wordlist()
        return 
	# 生成密码
    def get_words(self, http_response):
        # 将响应使用tostring函数转换为字符串，并使用split()函数以两个换行为条件分割一次
        # 这里是将响应头信息与响应体进行分割
        headers, body = http_response.tostring().split('\r\n\r\n', 1)
		# 将响应头在不区分大小写的情况下找到指定字符串
        # find(str, beg, end=)包含字符串返回相应索引，否则返回-1
        # 忽略下一个相应
        if headers.lower().find("content-type: text") == -1:
            return
		# 实例化对象
        tag_stripper = TagStripper()
        # 将body带入类进行解析
        page_text = tag_stripper.strip(body)
		# 找到所有以字母开头后跟着两个及以上单词的字符串
        words = re.findall("[a-zA-Z]\w{2,}", page_text)
		# 遍历加入集合
        for word in words:
			# 过滤超长字符串
            if len(word) <= 12:
                self.wordlist.add(word.lower())
        return 
	# 将一些常见关键字与密码组合
    def mangle(self, word):
        year = datetime.now().year
        suffixes = ["", "1", "!", year]
        mangled = []
		
        for password in (word, word.capitalize()):
            for suffix in suffixes:
                mangled.append("%s%s" % (password, suffix))

        return mangled
	# 遍历打印所有生成密码
    def display_wordlist(self):
        print "#!comment: BHP Wordlist for site(s) %s" % ", ".join(self.hosts)
		# sorted()函数，将列表里的所有元素进行排序
        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print password

        return
