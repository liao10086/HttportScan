# -*- coding: utf-8 -*-

'''
@File    ：scan.py
@IDE     ：PyCharm
@Author  ：Funsiooo
@Github  ：https://github.com/Funsiooo
'''

import json
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning
from modules.core.agent import User_Agent
from bs4 import BeautifulSoup
import chardet
from Wappalyzer import Wappalyzer, WebPage
from modules.core.icon import get_ico_url, get_hash



def scan_rule(response, url):
    warnings.filterwarnings('ignore', category=InsecureRequestWarning)

    headers = User_Agent()

    #response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)

    content = response.content
    encoding = chardet.detect(content)['encoding']

    try:
        if encoding != 'utf-8':
            html_body = content.decode('gbk')

        else:
            html_body = content.decode(encoding)
    except Exception as e:
        html_body = None

    header_string = str(response.headers)

    status_code = response.status_code

    try:
        soup = BeautifulSoup(html_body, 'html.parser')
        page_title = soup.find("title")
        title = page_title.get_text().strip()
    except Exception as e:
        title = None

    if status_code == 200:
        status_code = status_code
        if title is None or len(title) == 0:
            title = None

    elif status_code == 302:
        redirected_url = response.url
        redirected_response = requests.get(redirected_url, headers=headers, verify=False, timeout=5)
    
        if redirected_response.status_code == 200:
            soup = BeautifulSoup(redirected_response.content, 'html.parser')
            page_title = soup.find('title')
    
            try:
                title = page_title.get_text().strip()
            except Exception as e:
                title = None
    
            status_code = status_code
    
            if title is None or len(title) == 0:
                title = None

    else:
        status_code = status_code
        if title is None or len(title) == 0:
            title = None


    ico_content = requests.get(url=get_ico_url(url), headers=headers, timeout=5, verify=False).content
    ico_hash = get_hash(ico_content)


    with open('modules/config/finger.json', 'r', encoding='utf-8') as file:
        fingerprint = json.load(file)

    try:
        for fingerprints in fingerprint['fingerprint']:
            cms = fingerprints['cms']
            method = fingerprints['method']
            location = fingerprints['location']
            keywords = fingerprints['keyword']

            if html_body is not None:
                if method == 'keyword' and location == 'body':
                    found_keywords = all(keyword in html_body for keyword in keywords)
                    if found_keywords:
                        return cms, status_code, title

                elif method == 'icon_hash' and location == 'body':
                    found_keywords = all(keyword in ico_hash for keyword in keywords)
                    if found_keywords:
                        return cms, status_code, title

                elif method == 'keyword' and location == 'header':
                    for keyword in keywords:
                        if keyword in header_string:
                            return cms, status_code, title

                elif title is not None:
                    if method == 'keyword' and location == 'title':
                        found_keywords = all(keyword in title for keyword in keywords)
                        if found_keywords:
                            return cms, status_code, title

        return None, status_code, title
    except Exception as e:
        print(f"[-] Error occurred during URL identification,Check whether the network is normal: {str(e)}")



def httpportscan_main(response, url):

    global final_key
    try:
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)
        warnings.filterwarnings("ignore", category=UserWarning,
                                message="Caught 'unbalanced parenthesis at position 119'")
        webpage = WebPage.new_from_url(url, verify=False, timeout=5)

        wappalyzer = Wappalyzer.latest()
        wappalyzer.analyze(webpage)
        results = wappalyzer.analyze_with_categories(webpage)

        key_list = list(results.keys())

        if key_list:
            final_key = str(key_list).replace('[', '').replace(']', '').replace("'", '')
        else:
            final_key = ""

    except Exception as e:
        final_key = ""

    try:
        detected_cms, status_code, title = scan_rule(response, url)
        write_result = {"status_code":status_code, "detected_cms":detected_cms, "title":title, "final_key":final_key}
        #print(write_result)
        return write_result


    except Exception as e:
        pass
        print(e)
        # 捕获到异常的报错信息
        # print(f"{Colors.CYAN}{print_start_time()}{Colors.RESET} {Colors.RED}[-]{Colors.RESET}{Colors.BROWN} "
        #        f"[{status_code}]{Colors.RESET} {Colors.YELLOW}{url}{Colors.RESET} {Colors.RED} [Error occurred, Check whether the network and target link are entered correctly. If the link is redirected, identify the redirected link again]{Colors.RESET}")
        # print(f"[-] Error occurred during URL identification,Check whether the network is normal: {str(e)}")
        return {"status_code":"", "detected_cms":"", "title":"", "final_key":""}



