
import os, pandas, sys, logging, logging.handlers, yaml, datetime, requests, copy, glob, math
import argparse, json, subprocess, platform
from unifiapi.api import controller, UnifiApiError
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 0.1 initial version, copy from guard.py
# 1.9: small rework
# 1.10: small rework
# 1.11: small rework
# 1.12: speedtest, set timeout to 2 secs

version = 1.12

parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest="command")

refresh_parser = subparser.add_parser("refresh", help="Refresh list of AP's")

ping_parser =  subparser.add_parser("ping", help="x.x.x.x : ping x.x.x.x")
ping_parser.add_argument("ip", help="IP address to ping")
ping_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout")

speedtest_parser =  subparser.add_parser("speedtest", help="Start speedtest")
speedtest_parser.add_argument("--max", type=int, default=5, help="Maximum bandwidth in mbps")
speedtest_parser.add_argument("--duration", type=int, default=1, help="Test duration")
speedtest_parser.add_argument("--timeout", type=int, default=1, help="Timeout")
speedtest_parser.add_argument("--tries", type=int, default=25, help="Nbr of tries")

client_parser = subparser.add_parser("client", help="Iterate over a klas(sen) and block/unblock students")
client_parser.add_argument("--klas", help="All klassen with this pattern will be considered")
client_parser.add_argument("--list", help="Yaml file with a list of klassen to be considered")
client_parser.add_argument("--scope", help="Test scope, do a speedtest per <student,klass,alles>.  Default <student>", default="student")
client_parser.add_argument("--username", help="A student's username")
client_parser.add_argument("--timeout", type=int, default=1, help="Timeout per try")
client_parser.add_argument("--tries", type=int, default=25, help="Nbr of tries")
client_parser.add_argument("--test", help="If set, do not block/unblock clients", default=False, action="store_true")

ap_parser = subparser.add_parser("ap", help="Disable/Enable AP's matching name xxx")
ap_parser.add_argument("name", help="NAME, AP's matching name xxx")
ap_parser.add_argument("-e", "--enable", help="Enable AP's", action="store_true")
ap_parser.add_argument("-d", "--disable", help="Disable AP's", action="store_true")

ap_parser = subparser.add_parser("show", help="Show Status of AP's or Clients")
ap_parser.add_argument("-a", "--ap", help="Show status AP's", action="store_true")

parser.add_argument("--version", help="Return version", action="store_true")

args = parser.parse_args()

log = logging.getLogger("GUARD")
LOG_FILENAME = os.path.join(sys.path[0], f'log/unifi-guard.txt')
log.setLevel("INFO")
log_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1024 * 1024, backupCount=20)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

with open('unifiapi.yaml', "r") as cf:
    config = yaml.safe_load(cf)


def init_api(site_code=None):
    ctrlr = controller()
    if not site_code:
        site_code = config["default"]["site"]
    site = ctrlr.sites[site_code]()
    return site

def init_sdh():
    return config["sdh"]

# get all devices from the controller (switches and uaps)
def get_devices(site):
    try:
        devices = site.devices()
        devices = sorted(devices, key=lambda x: x["_id"])
        log.info(f"Retreived {len(devices)} devices from UNIFI controller")
        return devices
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e

def ping(ip, timeout = 1):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def speedtest_download(
    max_mbps: float = 5.0, test_duration: float = 5.0, timeout: float = 5.0, chunk_size: int = 64 * 1024,) -> float:
    session = requests.Session()
    retries = Retry(total=2, connect=2, read=2, backoff_factor=1, allowed_methods=["GET", "HEAD"],)
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Connection": "close",
        "Accept": "*/*",
    }

    start = time.perf_counter()
    bytes_read = 0

    try:
        with session.get(config["speedtest"]["url"], stream=True, timeout=timeout, headers=headers) as r:
            r.raise_for_status()

            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk:
                    continue

                bytes_read += len(chunk)
                elapsed = time.perf_counter() - start

                if elapsed >= test_duration:
                    break

                target_elapsed = (bytes_read * 8) / (max_mbps * 1_000_000)
                if target_elapsed > elapsed:
                    time.sleep(target_elapsed - elapsed)

    except requests.exceptions.RequestException as e:
        return 0.0

    elapsed = time.perf_counter() - start
    if elapsed <= 0:
        return 0.0
    return (bytes_read * 8) / elapsed / 1_000_000

def speedtest_loop(show_progress=False):
    speeds = []
    tries = 0
    while tries < args.tries:
        speed = int(speedtest_download(test_duration=args.timeout, timeout=args.timeout))
        speeds.append(speed)
        if (show_progress):
            print(f"{speeds}", end="\r")
        tries += 1
        if speed == 0:
            tries += 1
    print()
    return speeds

if args.version:
    print(f"Current version is {version}")

def unblock_client(site, mac):
    return block_client(site, mac, block=False)

def block_client(site, mac, block=True):
    try:
        if args.test: return
        if not ":" in mac:
            mac = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
        if block:
            site.c_block_client(**{"mac": mac})
        else:
            site.c_unblock_client(**{"mac": mac})
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.command == "speedtest":
    try:
        log.info(f"Start speedtest, {args.max}")
        # speed = speedtest_download(max_mbps=args.max, test_duration=args.duration, timeout=args.timeout)
        speeds = speedtest_loop(show_progress=True)
        print(f"Speeds {speeds}")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.command == "client":
    try:
        print(f"Start with args : {args}")
        log.info(f"Start with args : {args}")
        klas_list = []
        username = None
        if args.list:
            with open(args.list, "r") as lf:
                klas_list = yaml.load(lf, Loader=yaml.SafeLoader)
        elif args.klas:
            with open("ddos-klas-list.yaml", "r") as klf:
                klas_list = yaml.load(klf, Loader=yaml.SafeLoader)
                klas_list = [k for k in klas_list if args.klas in k]

        site = init_api()
        target_list = []
        if klas_list or args.username:
            with open("ddos-mac-list.json", "r") as mlf:
                mac_list_all = json.load(mlf)

            if klas_list:
                klas2item = {}
                for item in mac_list_all:
                    if item["klascode"] in klas2item:
                        klas2item[item["klascode"]].append(item)
                    else:
                        klas2item[item["klascode"]] = [item]
                for klas in klas_list:
                    target_list += [i for i in klas2item[klas]]
            elif args.username:
                for item in mac_list_all:
                    if item["username"].lower() == args.username.lower():
                        target_list = [item]
                        break

            if target_list:
                current_klas = target_list[0]["klascode"]
                blocked_macs = []
                # scope: student -> block student, speedtest, unblock
                # scope: klas -> block all students of said class, speedtest, unblock
                # scope alles -> block all students of all classes, speedtest, unblock
                for target in target_list:
                    if args.scope == "klas" and current_klas != target["klascode"]:
                        speeds = speedtest_loop(show_progress=True)
                        print(f"Speedtest klas {current_klas}, {speeds}")
                        log.info(f"Speedtest klas {current_klas}, {speeds}")
                        for unblock in blocked_macs:
                            print(f"Unblock client {unblock}")
                            log.info(f"Unblock client {unblock}")
                            unblock_client(site, unblock["mac"])
                        current_klas = target["klascode"]
                        blocked_macs = []
                    blocked_macs.append(target)
                    block_client(site, target["mac"])
                    if args.scope in ["klas", "alles"]:
                        print(f"Block client {target}")
                        log.info(f"Block client {target}")
                    if args.scope == "student":
                        speeds = speedtest_loop(show_progress=True)
                        print(f"Speedtest student {target}, {speeds}")
                        log.info(f"Speedtest student {target}, {speeds}")
                        unblock_client(site, target["mac"])
                        blocked_macs = []
                if blocked_macs:
                    speeds = speedtest_loop(show_progress=True)
                    if args.scope == "klas":
                        print(f"Speedtest klas {current_klas}, {speeds}")
                        log.info(f"Speedtest klas {current_klas}, {speeds}")
                    else:
                        print(f"Speedtest over alles, {speeds}")
                        log.info(f"Speedtest over alles, {speeds}")
                    for unblock in blocked_macs:
                        print(f"Unblock client {unblock}")
                        log.info(f"Unblock client {unblock}")
                        unblock_client(site, unblock["mac"])
            print(f"End, nbr clients: {len(target_list)}")
            log.info(f"End, nbr clients: {len(target_list)}")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.command == "ap":
    try:
        log.info(f"{"Disable" if args.disable else "Enable"} AP's")
        site = init_api()
        devices = []
        with open("ddos-ap-list.yaml", "r") as jf:
            all_devices = yaml.load(jf, Loader=yaml.SafeLoader)
            for d in all_devices:
                if args.name in d["name"]:
                    devices.append(d)
        for d in devices:
            log.info(f"{"Disable" if args.disable else "Enable"} {d["name"]}")
            site.put_device(d["id"], **{"disabled": args.disable})
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.command == "ping":
    try:
        start = datetime.datetime.now()
        ping_ok = ping(args.ip, args.timeout)
        print(ping_ok, datetime.datetime.now() - start)
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

def init_entra():
    return config["entra"]

def klas2klasgroep(klas):
    if klas[0] == "O":
        return klas
    if klas[0] in ["1", "2"]:
        return klas[:2]
    if " " in klas:
        return klas[:2]
    return klas

# From entra, get a list of devices and students.  Correlate and save as yaml file, with as parameters, name, class and device mac address
if args.command == "refresh":
    try:
        log.info("Start dumping student/mac address info into json/yaml file")
        device2student = {}
        entra_config = init_entra()
        ret = requests.get(entra_config["url_student"], headers={'x-api-key': entra_config["key"]})
        if ret.status_code == 200:
            res = ret.json()
            if res["status"]:
                device2student = {s["computer_name"]: s for s in res["data"]}
            else:
                log.error(f"could not get students from Entra, {res['data']}")
        mac_list = []
        klas_list = []
        ret = requests.get(entra_config["url_device"], headers={'x-api-key': entra_config["key"]})
        if ret.status_code == 200:
            res = ret.json()
            if res["status"]:
                for device in res["data"]:
                    if device["device_name"] in device2student:
                        student = device2student[device["device_name"]]
                        klascode = klas2klasgroep(student["klascode"])
                        mac_list.append({
                            "klascode": klascode,
                            "username": student["username"],
                            "naam": student["naam"],
                            "voornaam": student["voornaam"],
                            "mac": device["mac"]
                        })
                        klas_list.append(klascode)
            else:
                log.error(f"could not get devices from Entra, {res['data']}")
        if mac_list:
            with open("ddos-mac-list.json", "w") as jf:
                json.dump(mac_list, jf)
        if klas_list:
            klas_list = list(set(klas_list))
            klas_list.sort(reverse=True)
            with open("ddos-klas-list.yaml", "w") as jf:
                yaml.dump(klas_list, jf)
        log.info("Start dumping devices into json file")
        site = init_api()
        devices = get_devices(site)
        flat_list = []
        for d in devices:
            if "UAP" not in d["name"]: continue # skip everything except AP's
            flat = {"id": d.data["_id"], "state": d.data["state"], "name": d.data["name"]}
            if "disabled" in d.data:
                flat["disabled"] = d.data["disabled"]
            flat_list.append(flat)
        with open("ddos-ap-list.yaml", "w") as jf:
            yaml.dump(flat_list, jf)
        log.info(f"Done dumping devices to yaml file, {len(flat_list)} devices")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

# From entra, get a list of devices and students.  Correlate and save as yaml file, with as parameters, name, class and device mac address
if args.command == "show":
    try:
        if args.ap:
            log.info("Show disabled AP's")
            site = init_api()
            devices = get_devices(site)
            for d in devices:
                if "UAP" not in d["name"]: continue # skip everything except AP's
                if "disabled" in d.data and d.data["disabled"]:
                    log.info(f"AP Disabled: {d["name"]}")
                    print(f"AP Disabled: {d["name"]}")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')