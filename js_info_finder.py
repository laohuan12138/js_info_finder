# js file sensitive information collection tool
# by laohuan12138 https://github.com/laohuan12138


import requests
import urllib3
import re
urllib3.disable_warnings()
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from prettytable import PrettyTable
import optparse
import datetime

regex = {
    'Email' : r'(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))',
    'Oss云存储桶' : r'([A|a]ccess[K|k]ey[I|i]d|[A|a]ccess[K|k]ey[S|s]ecret|[Aa]ccess-[Kk]ey)|[A|a]ccess[K|k]ey',
    "aliyun_oss_url": r"[\\w.]\\.oss.aliyuncs.com",
    "secret_key": r"[Ss](ecret|ECRET)_?[Kk](ey|EY)",
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
#    'possible_Creds' : r"(?i)(" \
 #                   r"password\s*[`=:\"]+\s*[^\s]+|" \
 #                   r"password is\s*[`=:\"]*\s*[^\s]+|" \
 #                   r"pwd\s*[`=:\"]*\s*[^\s]+|" \
 #                   r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'Artifactory API Token': r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    'Artifactory Password': r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    'AWS Client ID': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
#    'Base64': r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}',
    'Basic Auth Credentials': r'(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+',
    'Cloudinary Basic Auth': r'cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
    "Facebook Client ID": r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}",
    "Facebook Secret Key": r"(?i)(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}",
    "Github": r"(?i)github(.{0,20})?['\"][0-9a-zA-Z]{35,40}",
    "Google Cloud Platform API Key": r"(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
    "LinkedIn Secret Key": r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
    'Mailchamp API Key': r"Mailchamp API Key",
    'Mailchamp API Key' : r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Mailgun API Key' : r'key-[0-9a-zA-Z]{32}',
    'Picatic API Key' : r'sk_live_[0-9a-z]{32}',
    'Slack Token' : r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    'Slack Webhook' : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'Stripe API Key' : r'(?:r|s)k_live_[0-9a-zA-Z]{24}',
    'Square Access Token' : r'sqOatp-[0-9A-Za-z\\-_]{22}',
    'Square Oauth Secret' : r'sq0csp-[ 0-9A-Za-z\\-_]{43}',
    "witter Oauth" : r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "Twitter Secret Key" : r"(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}",
    "国内手机号码" : r'1(3|4|5|6|7|8|9)\d{9}',
    "身份证号码" : r"[1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]",
    'IP地址' : r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    "Secret Key OR Private API" : "(access_key|Access-Key|access_token|SecretKey|SecretId|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps|AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc|password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot|files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_.\-,]{0,25}[a-z0-9A-Z_ .\-,]{0,25}(=|>|:=|\||:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{6,64})['\"]",
}

headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36'}
js_list = []
num = 0
table = PrettyTable()
table.field_names = ["id","Info_Name","Info_Value","From_Js_File"]
is_show = False
table.align = "l"

def check_url(url,js_url):
    if "http" in js_url:
        url = url
    else:
        url = urlparse(url)
        url = url.scheme+"://"+url.netloc+'/'+js_url
    js_list.append(url)


def send(url):
    try:
        rsp = requests.get(url,timeout=10,headers=headers,verify=False)
        rsp_raw = rsp.content.decode("utf-8")
        html = BeautifulSoup(rsp_raw,"html.parser")

        script_src = html.findAll("script")
        for html_script in script_src:
            script_l = html_script.get("src")
            if re.search(r'(\.js)$',str(script_l)):
                check_url(url,script_l)


    except:
        print("\033[31m[-] %s Request failed !\033[0m" % url)
        pass
#    print(js_list)

def send_js(url):
    global rsp_raws
    try:
        rsp = requests.get(url, timeout=10, headers=headers, verify=False)
        rsp_raw = rsp.content.decode("utf-8")
        rsp_raws = rsp_raw.replace(";",";\r\n").replace(",",",\r\n")

    except:
        print("\033[31m[-] %s Request failed !\033[0m" % url)

    regex_se(rsp_raws,url)

def regex_se(content,url):
    global num
    global is_show
    str_table = []
    str_len = len(content)

    for i in regex.items():
        match_start = 0
        reg_list = []
        while match_start < str_len:
            reg_cont = content[match_start:str_len]
            regex_result = re.search(i[1],reg_cont,re.IGNORECASE)
            if regex_result:
                match_start += regex_result.end() + 1
                is_show = True
                if regex_result.group() not in reg_list:
                    print("\033[32m [+] Found\033[0m"+"\033[31m {} \033[0m".format(i[0])+"\033[32m in {} \033[0m".format(url))
                    num += 1
                    reg_list.append(regex_result.group())

                    str_table.append(num)
                    str_table.append(i[0])
                    str_table.append(regex_result.group())
                    str_table.append(url)
                    table.add_row(str_table)
                str_table.clear()
    
            else:
                break

def print_table():
    if is_show:
        print(table.get_string())
        date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        with open(date+'.txt','a+') as f:
            f.write(table.get_string())
        print("\033[32m [+] 结果保存到 {} ！\033[0m".format(date+'.txt'))
    else:
        print("\033[32m [!] 未发现敏感信息!\033[0m")


def main():
    parser = optparse.OptionParser("python %prog -u http://127.0.0.1")
    parser.add_option('-u','--url',dest='url',help='输入一个URL，爬取URL中的所有js文件')
    parser.add_option('-f','--file',dest='file',help='批量爬取')
    parser.add_option('-j','--js',dest='js',help='输入指定的js文件')
    options,args = parser.parse_args()

    if options.url:
        url = options.url.strip()
        send(url)
    elif options.file:
        file = options.file
        with open(file,'r') as f:
            for i in f:
                send(i.strip())
    elif options.js:
        url = options.js
        send_js(url.strip())
    else:
        parser.error("查看帮助信息 python %prog -h")

    print("\033[32m [+] Found %d js files\033[0m" % (len(js_list)))
    print("\033[33m [+] start matching！\033[0m")
    for i in js_list:
        send_js(i.strip())

    print("\033[33m [+] A total of %d results were matched\033[0m" % (num))
    print_table()


if __name__ == '__main__':
    main()
