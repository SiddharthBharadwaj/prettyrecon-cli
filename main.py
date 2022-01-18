import argparse
from bs4 import BeautifulSoup
from config import email, password
import os
import requests
import sys
from time import sleep

def login():

    url='https://prettyrecon.com/api/v1/login'
    logindata = {"remember": "false", "email": email, "password": password}
    s.post(url, headers=headers, data=logindata)
    sleep(2)

def job():

    jobs='https://prettyrecon.com/target/running-jobs'
    status=True
    while True:
        if status == True:
            jobreq = s.get(jobs, headers=headers).content
            if 'Scan ID' in str(jobreq):
                status=True
                print("Tasks Pending....\nChecking again in 5 seconds.")
                sleep(5)
            else:
                break
        else:
            break


def sub():

    print("Subdomain Enumeration...")
    targetinfo=baseurl+'/info'
    subinfo=baseurl+'/subinfo'
    s.get(targetinfo, headers=headers)
    sleep(1)
    subreq = s.get(subinfo, headers=headers)
    if args.output is not None:
        job()
        soup = BeautifulSoup(subreq.content, "html.parser")
        scripts = (soup.find_all('script')[10].string.strip()[24:-2733]).encode().decode('unicode-escape')
        open(os.path.join(target, "subdomains.json"), 'w').write(scripts)


def basic():

    dnsinfo=baseurl+'/dnsinfo'
    ports=baseurl+'/ports'
    urls=baseurl+'/urls'
    

    print("DNS Info...")
    dnsreq = s.get(dnsinfo, headers=headers)
    sleep(1)
    print("Port Scan...")
    portreq = s.get(ports, headers=headers)
    sleep(1)
    print("Waybackurls...")
    s.get(urls, headers=headers)
    if args.output is not None:
        job()
        dnssoup = BeautifulSoup(dnsreq.content, "html.parser")
        portsoup = BeautifulSoup(portreq.content, "html.parser")
        dnsjson = (dnssoup.find_all('script')[10].string.strip()[34:-2905]).encode().decode('unicode-escape')
        portjson = (portsoup.find_all('script')[10].string.strip()[44:-2939]).encode().decode('unicode-escape')
        open(os.path.join(target, "dnsinfo.json"), 'w').write(dnsjson)
        open(os.path.join(target, "ports.json"), 'w').write(portjson)
        urldownload = s.get(url = urls+'?download=txt', allow_redirects=True)
        open(os.path.join(target, 'waybackurls.txt'), 'wb').write(urldownload.content)


def vuln():

    subtko=baseurl+'/takeover_subdomain_scan'
    cve=baseurl+'/cves_scan'
    common=baseurl+'/vulnerability_detection'
    exposed=baseurl+'/exposed_secret'
    miscofig=baseurl+'/security_misconf_scan'

    print("Subdomain Takeover...")
    subtkoreq = s.get(subtko, headers=headers)
    sleep(1)
    print("Scanning for CVE's...")
    cvereq = s.get(cve, headers=headers)
    sleep(1)
    print("Scanning for common vulnerabilities...")
    commonreq = s.get(common, headers=headers)
    sleep(1)
    print("Scanning for exposed secrets...")
    exposedreq = s.get(exposed, headers=headers)
    sleep(1)
    print("Scanning for security misconfigurations...")
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
        open(os.path.join(target, "subtko.json"), 'w').write(tkojson)
        open(os.path.join(target, "cves.json"), 'w').write(cvejson)
        open(os.path.join(target, "common_vulns.json"), 'w').write(commonjson)
        open(os.path.join(target, "exposed_cred.json"), 'w').write(exposedjson)
        open(os.path.join(target, "misc_vulns.json"), 'w').write(miscjson)
        



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
        print("Please select a valid scan type, i.e all,basic,vuln,sub.")
        sys.exit()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PrettyRecon CLI')
    parser.add_argument("-t", "--target", help="Supply the target to scan.", required=True)
    parser.add_argument("-st", "--scan_type", help="all: Full scan, basic: Basic scan, vuln: Scan for vulns only, sub: Subdomains only", required=True)
    parser.add_argument("-o", "--output", help="Saves output to json file. Usage: main.py -t TARGET -st SCANTYPE -o filename(default is output.txt)", nargs='?', const='1')
    args = parser.parse_args()
    target = args.target
    type = args.scan_type
    s = requests.Session()
    baseurl='https://prettyrecon.com/target/'+target
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"}
    if args.output is not None:
        if not os.path.exists(target):
            os.makedirs(target)

    main()