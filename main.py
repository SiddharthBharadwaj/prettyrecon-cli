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

def initjob(flag):

    if flag==0:
        mydivs = BeautifulSoup(s.get(jobs, headers=headers).content, "html.parser").find_all("div", {"class": "well animated slideInUp"})
        for tag in mydivs:
            if 'id' in tag.attrs:
                runningjobs.append(tag['id'])
    elif flag==1:
        mydivs = BeautifulSoup(s.get(jobs, headers=headers).content, "html.parser").find_all("div", {"class": "well animated slideInUp"})
        for tag in mydivs:
            if 'id' in tag.attrs:
                if tag['id'] not in runningjobs:
                    print("Job with ID "+tag['id']+" Started!")
                    joblist.append(tag['id'])

def job():

    status=True
    while status==True:
        mydivs = BeautifulSoup(s.get(jobs, headers=headers).content, "html.parser").find_all("div", {"class": "well animated slideInUp"})
        ids = [tag['id'] for tag in mydivs if 'id' in tag.attrs]
        if any(item in joblist for item in ids):
            status=True
            sys.stdout.write('■')
            sys.stdout.flush()
            sleep(5)
        else:
            status=False
            break

def deltemp():

    if os.path.exists(os.path.join(dir, ".temp.html")):
        os.remove(os.path.join(dir, ".temp.html"))


def sub():

    print(bcolors.BOLD + "Subdomain Enumeration..." + bcolors.ENDC)
    targetinfo=baseurl+'/info'
    subinfo=baseurl+'/subinfo'
    s.get(targetinfo, headers=headers)
    sleep(1)
    subreq = s.get(subinfo, headers=headers)
    initjob(1)
    if args.output is not None:
        job()
        soup = BeautifulSoup(subreq.content, "html.parser")
        subjson = (soup.find_all('script')[10])
        open(os.path.join(dir, ".temp.html"), 'w').write(str(subjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data = JSON.parse" in line: open(os.path.join(dir, "subdomains.json"), 'w').write(line.strip()[23:-3].encode().decode('unicode-escape'))



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
    sleep(1)
    initjob(1)
    if args.output is not None:
        job()
        dnssoup = BeautifulSoup(dnsreq.content, "html.parser")
        portsoup = BeautifulSoup(portreq.content, "html.parser")
        dnsjson = (dnssoup.find_all('script')[10])
        portjson = (portsoup.find_all('script')[10])
        open(os.path.join(dir, ".temp.html"), 'w').write(str(dnsjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "dnsinfo.json"), 'w').write(line.strip()[11:-1].encode().decode('unicode-escape'))
        open(os.path.join(dir, ".temp.html"), 'w').write(str(portjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "ports.json"), 'w').write(line.strip()[11:-1].encode().decode('unicode-escape'))
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
    sleep(1)
    initjob(1)
    if args.output is not None:
        job()
        tkosoup = BeautifulSoup(subtkoreq.content, "html.parser")
        cvesoup = BeautifulSoup(cvereq.content, "html.parser")
        commonsoup = BeautifulSoup(commonreq.content , "html.parser")
        exposedsoup = BeautifulSoup(exposedreq.content , "html.parser")
        miscsoup = BeautifulSoup(miscreq.content , "html.parser")
        tkojson = (tkosoup.find_all('script')[10])
        cvejson = (cvesoup.find_all('script')[10])
        commonjson = (commonsoup.find_all('script')[10])
        exposedjson = (exposedsoup.find_all('script')[10])
        miscjson = (miscsoup.find_all('script')[10])
        open(os.path.join(dir, ".temp.html"), 'w').write(str(tkojson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "subtko.json"), 'w').write(line.strip()[12:-2].encode().decode('unicode-escape'))
        open(os.path.join(dir, ".temp.html"), 'w').write(str(cvejson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "cves.json"), 'w').write(line.strip()[12:-2].encode().decode('unicode-escape'))
        open(os.path.join(dir, ".temp.html"), 'w').write(str(commonjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "common_vulns.json"), 'w').write(line.strip()[12:-2].encode().decode('unicode-escape'))
        open(os.path.join(dir, ".temp.html"), 'w').write(str(exposedjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "exposed_creds.json"), 'w').write(line.strip()[12:-2].encode().decode('unicode-escape'))
        open(os.path.join(dir, ".temp.html"), 'w').write(str(miscjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data =" in line: open(os.path.join(dir, "misc_vulns.json"), 'w').write(line.strip()[12:-2].encode().decode('unicode-escape'))     



def main():

    if (type=='all'):
        login()
        initjob(0)
        sub()
        basic()
        vuln()
        deltemp()
    elif (type=='basic'):
        login()
        initjob(0)
        sub()
        basic()
        deltemp()
    elif (type=='vuln'):
        login()
        initjob(0)
        sub()
        vuln()
        deltemp()
    elif (type=='sub'):
        login()
        initjob(0)
        sub()
        deltemp()
    else:
        print(bcolors.FAIL + "Please select a valid scan type, i.e all,basic,vuln,sub." + bcolors.ENDC)
        sys.exit()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PrettyRecon CLI')
    parser.add_argument("-t", "--target", help="Supply the target to scan.", required=True)
    parser.add_argument("-st", "--scan_type", help="all: Full scan, basic: Basic scan, vuln: Scan for vulns only, sub: Subdomains only", required=True)
    parser.add_argument("-o", "--output", help="Saves output to output/*.json file. Usage: main.py -t TARGET -st SCANTYPE -o", nargs='?', const='1')
    args = parser.parse_args()
    target = args.target
    type = args.scan_type
    dir = "output/"+target
    jobs='https://prettyrecon.com/target/running-jobs'
    runningjobs=[]
    joblist=[]
    s = requests.Session()
    baseurl='https://prettyrecon.com/target/'+target
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"}
    if args.output is not None:
        if not os.path.exists(dir):
            os.makedirs(dir)

    main()