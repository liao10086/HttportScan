#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import json
import multiprocessing
import random
from concurrent import futures
from urllib.parse import urlparse
import subprocess
import argparse

import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from Wappalyzer.Wappalyzer import Wappalyzer, WebPage
from wafw00f.wafcheck import wafcheck
from modules.core.scanfinger import httpportscan_main

requests.adapters.DEFAULT_RETRIES = 5
requests.packages.urllib3.disable_warnings()

table = PrettyTable(['URL','标题','状态码','WEB指纹','WAF','登录后台'])

'''
author by liao
2023-08-28
'''

class PortScan(object):
    def __init__(self):
        self.version = "1.1"
        self.http_time_out = 5  # 配置HTTP请求超时时间
        self.pool_max_workers = 100  # 配置线程池
        self.url_list = []
        self.dict_url = []
        self.dir_result = []
        #self.table = PrettyTable(['URL','标题','状态码','WEB指纹','WAF','登录后台'])
        #非HTPP端口排除，罗列不全可以自行添加
        self.not_http_ports = {
                                21: "FTP",
                                22: "SSH",
                                23: "TELNET",
                                25: "SMTP",
                                53: "DNS",
                                110: "POP3",
                                143: "IMAP",
                                161: "SNMP",
                                445: "SMB",
                                465: "SMTPS",
                                1521: "ORACLE",
                                1433: "MSSQL",
                                3306: "MySQL",
                                3389: "RDP",
                                5432: "PostgreSQL",
                                6379: "Redis",
                                27071: "MongoDB"
                                }
        self.parser = argparse.ArgumentParser(description="Zionlab快速端口识别工具")
        self._add_arguments()
        self.target, self.file,self.waf, self.show = self.process_args()

    def _add_arguments(self):
        self.parser.add_argument('-t', '--target', required=False, help='扫描单个目标,支持192.168.0.1, 192.168.0.1-100, 192.168.0.1-192.168.0.100三种格式')
        self.parser.add_argument('-f', '--file', required=False, help='扫描目标文件')
        self.parser.add_argument('-w', '--waf', required=False, action='store_true', help='是否启用WAF检测,默认不启用')
        self.parser.add_argument('-s', '--show', required=False, action='store_true', help='列表只展示HTTP服务的信息,默认全展示')
        
    def process_args(self):
        args = self.parser.parse_args()
        target = args.target
        file = args.file
        waf = args.waf
        show = args.show
        return target, file, waf, show

    def expand_ip_range(self, ip_range):
        '''
        支持输入:
               192.168.0.1-255
               192.168.0.1-192.168.0.255
        '''
        ip_list = []

        # 检查是否是第一种格式：192.168.0.1-255
        if '-' in ip_range and (len(ip_range)-len(ip_range.replace(".",""))) ==3:
            start, end = ip_range.split('-')
            network_prefix = '.'.join(start.split('.')[:-1])
            for i in range(int(start.split('.')[-1]), int(end) + 1):
                ip = f"{network_prefix}.{i}"
                ip_list.append(ip)
        if '-' in ip_range and (len(ip_range)-len(ip_range.replace(".",""))) ==6:
            # 第二种格式：192.168.0.1-192.168.0.255
            start, end = ip_range.split('-')
            network_prefix = '.'.join(start.split('.')[:-1])
            for i in range(int(start.split('.')[-1]), int(end.split('.')[-1]) + 1):
                ip = f"{network_prefix}.{i}"
                ip_list.append(ip)
        
        return ip_list

    def is_valid_ip_range(self, ip_range):
        '''
        校验是否为以下两种格式:
               192.168.0.1-255
               192.168.0.1-192.168.0.255
        '''
        ip_range_pattern1 = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
        ip_range_pattern2 = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$'
        # 使用正则表达式匹配字符串
        if re.match(ip_range_pattern1, ip_range):
            return True
        if re.match(ip_range_pattern2, ip_range):
            return True
        else:
            return False


    def scan(self, target):
        print('=' * 80)
        self.get_url_list(target)
        if self.url_list != [] and isinstance(self.url_list, list):
            self.url_scan()
        elif self.url_list == -1:
            print("[-]执行失败，检查docker是否启动和rustscan/rustscan:2.1.1镜像是否存在")
        else:
            print("[-] {} 未识别到HTTP存活端口".format(target))

    def main(self):
        self.get_show_banner()
        if self.target is not None:
            if self.is_valid_ip_range(self.target):
                targets = self.expand_ip_range(self.target)
                for target in targets:
                    self.scan(target)
            else:
                self.scan(self.target)
        if self.file is not None:
            with open(self.file, 'r') as f:
                targets = f.readlines()
                for target in targets:
                    target = target.strip()
                    if target != "":
                        if self.is_valid_ip_range(target):
                            ts = self.expand_ip_range(target)
                            for t in ts:
                                self.scan(t)
                        else:
                            self.scan(target)


    #全端口存活检测
    def find_ports(self, target):
        cmd = 'docker run -it --rm --name rustscan rustscan/rustscan:2.1.1 -r 1-65535 -g  -t 5000 -a {}'.format(target)
        result = subprocess.run(cmd, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ports_str = result.stdout
        print("端口识别结果如下:")
        print(ports_str)
        return ports_str



    def get_url_list(self, target):
        try:
            self.url_list = []
            content = self.find_ports(target)
            #测试使用
            #content = "10.50.24.152 -> [8881]"

            '''
            rustscan返回结果示例如下：
            127.0.0.1 -> [22,443,5443,6442,6444,6443,7443,8021,8080,8443,9001,9003,9002,10087]

            '''
            if content.strip() != "":

                result = content.strip().replace(" ","").split("->")
                ip = result[0]
                ports = result[1].replace("[","").replace("]","").split(",")

                if len(ports) != 0:
                    for port in ports:
                        if int(port) in self.not_http_ports.keys():
                            print("\033[32m端口:{} 服务:{}\033[0m".format(port, self.not_http_ports[int(port)]))
                            continue
                        if port != "443":
                            self.url_list.append("http://{}:{}".format(ip, port))
                        if port != "80":
                            self.url_list.append("https://{}:{}".format(ip, port))
                print(f"{target} URL探测任务读取完毕，识别到 {len(self.url_list)} 条任务信息")
        except subprocess.CalledProcessError:
            self.url_list = -1



    def url_scan(self):
        global table
        process_name = multiprocessing.current_process().name
        #print("【URL扫描线程启动】" + process_name)
        pool = futures.ThreadPoolExecutor(max_workers=self.pool_max_workers)
        wait_for = [pool.submit(self.action, task_url, table) for task_url in self.url_list]
        futures.wait(wait_for)
        print(table)
        #扫描结束后清空数据，防止数据混淆在下一个任务里
        table.clear_rows()

    def get_show_banner(self):
        print("""\033[32m
                ZionLab 快速IP全端口检查工具
                \033[0m
                """)

    @staticmethod
    def gen_fake_header():
        """
        生成伪造请求头
        """
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
            'Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0']
        ua = random.choice(user_agents)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,'
                      'application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Cache-Control': 'max-age=0',
            'Connection': 'close',
            'DNT': '1',
            'Cookie': 'BIDUPSID=564f939a8f8a5befa67d62bdf79e6fa5; PSTM=1605847972; BAIDUID=d9e45923b4fb84761b608da331c2d66c:FG=1;',
            'Referer': 'https://www.baidu.com/',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua
        }
        return headers

    def get_title(self, markup):
        """
        获取网页标题
        """
        try:
            soup = BeautifulSoup(markup, 'lxml')
        except Exception as e:
            #print(f"【无法获取标题】{e}")
            return None
        title = soup.title
        if title:
            return title.text.strip()
        h1 = soup.h1
        if h1:
            return h1.text.strip()
        h2 = soup.h2
        if h2:
            return h2.text.strip()
        h3 = soup.h3
        if h2:
            return h3.text.strip()
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc:
            return desc['content'].strip()
        word = soup.find('meta', attrs={'name': 'keywords'})
        if word:
            return word['content'].strip()
        if len(markup) <= 200:
            return markup.strip()
        text = soup.text
        if len(text) <= 200:
            return text.strip()
        return None


    def get_banner_new(self, response, url):
        #通过chunsou获取指纹信息
        banner = ""
        try:
            result = httpportscan_main(response, url)
            banner = "\033[32m" + result["detected_cms"] +"\033[0m|" + result["final_key"]
        except Exception as e:
            pass
            return ""
        return banner

    def check_http(self, sql_ports):
        '''HTTP服务探测'''
        url = f'{sql_ports}'
        # 随机获取一个Header头
        headers = self.gen_fake_header()
        try:
            response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
        except requests.exceptions.Timeout:
            pass
            return None
        except requests.exceptions.SSLError:
            st_sql_ports = urlparse(sql_ports).netloc
            url = f'https://{st_sql_ports}'
            try:
                response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
            except Exception as e:
                return None
            else:
                return response
        # 报错判断为没有加HTTP头
        except Exception as e:
            #print("【没有HTTP头，自动添加】" + url)
            # sql_ports = urlparse(sql_ports).netloc
            url = f'http://{sql_ports}'
            try:
                response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
            except requests.exceptions.Timeout:
                pass
                return None
            # SSL错误，说明要HTTPS访问
            except requests.exceptions.SSLError:
                url = f'https://{sql_ports}'
                try:
                    response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
                except Exception as e:
                    return None
                else:
                    return response
            except Exception as e:
                url = f'https://{sql_ports}'
                try:
                    response = requests.get(url, timeout=self.http_time_out, verify=False, headers=headers)
                except Exception as e:
                    pass
                    return None
                else:
                    return response

            else:
                return response
        else:
            return response

    def action(self, task_url, table):
        res = self.check_http(task_url)
        try:
            task_domain = urlparse(task_url)
            res_title = ""
            fig = ""
            status_code = ""
            waf = ""
            backend = ""
            if res is None:
                res_url = task_url
            else:
                res.encoding = res.apparent_encoding
                task_domain = urlparse(res.url)
                res_url = res.url
                #fig = self.get_banner(res)
                if res.status_code == 200:
                    fig = self.get_banner_new(res, task_url).strip("|")
                status_code = res.status_code
                res_title = self.get_title(markup=res.text)
                if status_code == 200:
                    if self.waf:
                        flag, waf = wafcheck(res_url)
                    else:
                        flag, waf = True, "不检查"
                    if not flag:
                        waf = ''
                    if waf!=[] and waf!="" and waf!="不检查":
                        waf = "\033[31m" +str(waf) +"\033[0m"
                if "登录" in res_title or "后台" in res_title or "管理" in res_title or "登陆" in res_title or "login" in res_title.lower():
                    backend = "\033[32m是\033[0m"
                else:
                    backend = "否"
                if status_code == 200:
                    status_code = "\033[32m200\033[0m"

            if res_title is None:
                res_title = ""
                backend = "否"

            csv_res = {
                'url': res_url,
                '标题': res_title,
                'http状态码': status_code,
                'web指纹': fig,
                'WAF': waf,
                '登录后台': backend
            }
            #print([res_url, res_title, status_code, fig, waf, backend])
            if not self.show:
                table.add_row([res_url, res_title, status_code, fig, waf, backend])
            else:
                if status_code != "":
                    table.add_row([res_url, res_title, status_code, fig, waf, backend])
            return csv_res

        except Exception as e:
            pass
            #print(e)


if __name__ == '__main__':
    
    Scan = PortScan()
    Scan.main()

    
    #httpportscan_main("http://127.0.0.1")
    #print(main("https://127.0.0.1:8888"))

