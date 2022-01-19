import argparse
from bs4 import BeautifulSoup
from config import email, password
import os
import requests
import sys
from time import sleep

class bcolors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def login():

    url='https://prettyrecon.com/api/v1/login'
    logindata = {"remember": "false", "email": email, "password": password}
    loginreq = s.post(url, headers=headers, data=logindata)
    if 'Wrong email or password' in str(loginreq.content):
        print(bcolors.FAIL + "Login Failed: Wrong credentials, please check config." + bcolors.ENDC)
        sys.exit()
    elif 'prettyRECON - Dashboard' and 'Logout' in str(loginreq.content):
        print(bcolors.GREEN + "Login Success!" + bcolors.ENDC)
        loginstatus = True
    else:
        print(bcolors.FAIL + 'Unknown Error!' + bcolors.ENDC)
    sleep(2)

def job():

    jobs='https://prettyrecon.com/target/running-jobs'
    status=True
    while True:
        if status == True:
            jobreq = s.get(jobs, headers=headers).content
            if 'Scan ID' in str(jobreq):
                status=True
                print(bcolors.BLUE + "Tasks Pending....\nChecking again in 5 seconds." + bcolors.ENDC)
                sleep(5)
            else:
                break
        else:
            break


def sub():

    print(bcolors.BOLD + "Subdomain Enumeration..." + bcolors.ENDC)
    targetinfo=baseurl+'/info'
    subinfo=baseurl+'/subinfo'
    s.get(targetinfo, headers=headers)
    sleep(1)
    subreq = s.get(subinfo, headers=headers)
    if args.output is not None:
        job()
        soup = BeautifulSoup(subreq.content, "html.parser")
        scripts = (soup.find_all('script')[10].string.strip()[24:-2733]).encode().decode('unicode-escape')
        open(os.path.join(dir, "subdomains.json"), 'w').write(scripts)


def basic():

    dnsinfo=baseurl+'/dnsinfo'
    ports=baseurl+'/ports'
    urls=baseurl+'/urls'
    

    print(bcolors.BOLD + "DNS Info..." + bcolors.ENDC)
    dnsreq = s.get(dnsinfo, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Port Scan..." + bcolors.ENDC)
    portreq = s.get(ports, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Waybackurls..." + bcolors.ENDC)
    s.get(urls, headers=headers)
    if args.output is not None:
        job()
        dnssoup = BeautifulSoup(dnsreq.content, "html.parser")
        portsoup = BeautifulSoup(portreq.content, "html.parser")
        dnsjson = (dnssoup.find_all('script')[10].string.strip()[34:-2905]).encode().decode('unicode-escape')
        portjson = (portsoup.find_all('script')[10].string.strip()[44:-2939]).encode().decode('unicode-escape')
        open(os.path.join(dir, "dnsinfo.json"), 'w').write(dnsjson)
        open(os.path.join(dir, "ports.json"), 'w').write(portjson)
        urldownload = s.get(url = urls+'?download=txt', allow_redirects=True)
        open(os.path.join(dir, 'waybackurls.txt'), 'wb').write(urldownload.content)


def vuln():

    subtko=baseurl+'/takeover_subdomain_scan'
    cve=baseurl+'/cves_scan'
    common=baseurl+'/vulnerability_detection'
    exposed=baseurl+'/exposed_secret'
    miscofig=baseurl+'/security_misconf_scan'

    print(bcolors.BOLD + "Subdomain Takeover..." + bcolors.ENDC)
    subtkoreq = s.get(subtko, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for CVE's..." + bcolors.ENDC)
    cvereq = s.get(cve, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for common vulnerabilities..." + bcolors.ENDC)
    commonreq = s.get(common, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for exposed secrets..." + bcolors.ENDC)
    exposedreq = s.get(exposed, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for security misconfigurations..." + bcolors.ENDC)
    miscreq = s.get(miscofig, headers=headers)
    if args.output is not None:
        job()
        tkosoup = BeautifulSoup(subtkoreq.content, "html.parser")
        cvesoup = BeautifulSoup(cvereq.content, "html.parser")
        commonsoup = BeautifulSoup(commonreq.content , "html.parser")
        exposedsoup = BeautifulSoup(exposedreq.content , "html.parser")
        miscsoup = BeautifulSoup(miscreq.content , "html.parser")
        tkojson = (tkosoup.find_all('script')[10].string.strip()[11:-2396]).encode().decode('unicode-escape')
        cvejson = (cvesoup.find_all('script')[10].string.strip()[12:-2377]).encode().decode('unicode-escape')
        commonjson = (commonsoup.find_all('script')[10].string.strip()[12:-2391]).encode().decode('unicode-escape')
        exposedjson = (exposedsoup.find_all('script')[10].string.strip()[12:-2453]).encode().decode('unicode-escape')
        miscjson = (miscsoup.find_all('script')[10].string.strip()[12:-2386]).encode().decode('unicode-escape')
        open(os.path.join(dir, "subtko.json"), 'w').write(tkojson)
        open(os.path.join(dir, "cves.json"), 'w').write(cvejson)
        open(os.path.join(dir, "common_vulns.json"), 'w').write(commonjson)
        open(os.path.join(dir, "exposed_cred.json"), 'w').write(exposedjson)
        open(os.path.join(dir, "misc_vulns.json"), 'w').write(miscjson)
        



def main():

    if (type=='all'):
        login()
        sub()
        basic()
        vuln()
    elif (type=='basic'):
        login()
        sub()
        basic()
    elif (type=='vuln'):
        login()
        sub()
        vuln()
    elif (type=='sub'):
        login()
        sub()
    else:
        print(bcolors.FAIL + "Please select a valid scan type, i.e all,basic,vuln,sub." + bcolors.ENDC)
        sys.exit()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PrettyRecon CLI')
    parser.add_argument("-t", "--target", help="Supply the target to scan.", required=True)
    parser.add_argument("-st", "--scan_type", help="all: Full scan, basic: Basic scan, vuln: Scan for vulns only, sub: Subdomains only", required=True)
    parser.add_argument("-o", "--output", help="Saves output to json file. Usage: main.py -t TARGET -st SCANTYPE -o filename(default is output.txt)", nargs='?', const='1')
    args = parser.parse_args()
    target = args.target
    type = args.scan_type
    dir = "output/"+target
    s = requests.Session()
    baseurl='https://prettyrecon.com/target/'+target
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"}
    if args.output is not None:
        if not os.path.exists(dir):
            os.makedirs(dir)

    main()