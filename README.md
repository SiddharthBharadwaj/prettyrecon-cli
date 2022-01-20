# PrettyRecon-cli
PrettyRecon-cli is an unofficial cli client for [PrettyRecon](https://prettyrecon.com/).

This tool can be used to trigger various tasks on prettyrecon as well as fetch output of those tasks/scans.

As PrettyRecon currently does not have any api feature available, prettyrecon-cli uses email and password for authentication. None of these are saved or shared anywhere other than your computer where it is running.

## Setup

1. Clone the repository

```bash
$ git clone https://github.com/SiddharthBharadwaj/prettyrecon-cli.git
```

2. Install the dependencies

```bash
$ cd prettyrecon-cli
$ pip3 install -r requirements.txt
```
3. Update config.py with valid credentials

4. Run prettyrecon-cli (see [Usage](#usage) below for more detail)

```bash
$ python3 main.py -t example.com -st scantype
```

## Usage

```bash
$ python3 main.py --help
usage: main.py [-h] -t TARGET -st SCAN_TYPE [-o [OUTPUT]]

PrettyRecon CLI

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Supply the target to scan.
  -st SCAN_TYPE, --scan_type SCAN_TYPE
                        all: Full scan, basic: Basic scan, vuln: Scan for
                        vulns only, sub: Subdomains only
  -o [OUTPUT], --output [OUTPUT]
                        Saves output to output/*.json file. Usage: main.py -t
                        TARGET -st SCANTYPE -opython3 main.py --help
```

Tested on Python 3.9.7. Feel free to [open an issue](https://github.com/christophetd/cloudflair/issues/new) if you have bug reports,feature requests questions.
Contributions are most welcome!
