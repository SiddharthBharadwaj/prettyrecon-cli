import argparse
import shutil
from bs4 import BeautifulSoup
from config import email, password
from filesplit.split import Split
import os
import requests
import sys
from time import sleep
import validators


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

    if os.path.exists(os.path.join(str(dir), ".temp.html")):
        os.remove(os.path.join(str(dir), ".temp.html"))


def sub():

    print(bcolors.BOLD + "Subdomain Enumeration..." + bcolors.ENDC)
    targetinfo=baseurl+'/info'
    subinfo=baseurl+'/subinfo'
    s.get(targetinfo, headers=headers)
    sleep(1)
    s.get(subinfo, headers=headers)
    initjob(1)
    if args.output:
        job()
        soup = BeautifulSoup(s.get(subinfo, headers=headers).content, "html.parser")
        subjson = (soup.find_all('script')[10])
        open(os.path.join(dir, ".temp.html"), 'w').write(str(subjson))
        for line in open(os.path.join(dir, ".temp.html"), 'r'):
            if "var data = JSON.parse" in line: open(os.path.join(dir, "subdomains.json"), 'w').write(line.strip()[23:-3].encode().decode('unicode-escape'))


def basic():

    dnsinfo=baseurl+'/dnsinfo'
    ports=baseurl+'/ports'
    urls=baseurl+'/urls'

    print(bcolors.BOLD + "DNS Info..." + bcolors.ENDC)
    s.get(dnsinfo, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Port Scan..." + bcolors.ENDC)
    s.get(ports, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Waybackurls..." + bcolors.ENDC)
    s.get(urls, headers=headers)
    sleep(1)
    initjob(1)
    if args.output:
        job()
        dnssoup = BeautifulSoup(s.get(dnsinfo, headers=headers).content, "html.parser")
        portsoup = BeautifulSoup(s.get(ports, headers=headers).content, "html.parser")
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
    s.get(subtko, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for CVE's..." + bcolors.ENDC)
    s.get(cve, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for common vulnerabilities..." + bcolors.ENDC)
    s.get(common, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for exposed secrets..." + bcolors.ENDC)
    s.get(exposed, headers=headers)
    sleep(1)
    print(bcolors.BOLD + "Scanning for security misconfigurations..." + bcolors.ENDC)
    s.get(miscofig, headers=headers)
    sleep(1)
    initjob(1)
    if args.output:
        job()
        tkosoup = BeautifulSoup(s.get(subtko, headers=headers).content, "html.parser")
        cvesoup = BeautifulSoup(s.get(cve, headers=headers).content, "html.parser")
        commonsoup = BeautifulSoup(s.get(common, headers=headers).content , "html.parser")
        exposedsoup = BeautifulSoup(s.get(exposed, headers=headers).content , "html.parser")
        miscsoup = BeautifulSoup(s.get(miscofig, headers=headers).content , "html.parser")
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


def CustomSumScan():
    if os.path.exists(args.customsubscan):
            url = "https://prettyrecon.com:443/tools/custom_subdomains"
            if not os.path.exists('Splits'):
                os.makedirs('Splits')
            filename=args.customsubscan
            split = Split(inputfile=filename, outputdir='Splits')
            split.bylinecount(300)
            _, _, files = next(os.walk("Splits"))
            file_count = len(files)
            n = 1
            while file_count != 1:
                file = open('Splits/'+filename[:-4]+"_"+str(n)+".txt")
                datap = file.read().replace('\n', '\r\n')
                data = {"scanname": "CliScan", "subdomains": datap}
                s.post(url, headers=headers, data=data)
                initjob(1)
                job()
                file_count-=1
                n+=1
            shutil.rmtree("Splits") 
            print("CustomSubScan Finished!")   
    else:
        print(bcolors.FAIL + "Path/File at "+args.customsubscan+"not found!" + bcolors.ENDC)
        sys.exit()


def main():

    if args.customsubscan:
        login()
        initjob(0)
        CustomSumScan()
    elif args.target and args.scan_type:
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
    else:
        print(bcolors.FAIL + "Please pass valid arguments! i.e. Either '-t' and '-st' for normal scan OR '-cscn' for CustomSubScan" + bcolors.ENDC)
        sys.exit()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PrettyRecon CLI')
    parser.add_argument("-t", "--target", help="Supply the target to scan.")
    parser.add_argument("-st", "--scan_type", help="all: Full scan, basic: Basic scan, vuln: Scan for vulns only, sub: Subdomains only", required='--target' in sys.argv)
    parser.add_argument("-o", "--output", help="Saves output to output/*.json file.")
    parser.add_argument("-cscn", "--customsubscan", help="For the CustomSubScan feature of PrettyRecon. Pass filename after flag.")
    args = parser.parse_args()
    target = args.target
    type = args.scan_type
    if args.output is not None:
        dir = str(args.output)+"/"+target
        if not os.path.exists(dir):
            os.makedirs(dir)
    jobs='https://prettyrecon.com/target/running-jobs'
    runningjobs=[]
    joblist=[]
    s = requests.Session()
    if args.target and (args.scan_type is None):
        parser.error("Missing argument '-st/--scan_type' ")
    elif args.target:
        if validators.domain(target):
            baseurl='https://prettyrecon.com/target/'+target
        else:
           print(bcolors.FAIL + "Check the target and try again!\nExample of a valid target: example.com [Without http(s) and '/']" + bcolors.ENDC)
           sys.exit()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36"}

    main()