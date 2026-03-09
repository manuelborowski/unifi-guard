# Disable/enable wireless clients
# From entra, get a list of all students and all devices.  Match the devices with the students and save to config file
# Extract the classes and save to seperate file
# Loop over devices, associated with students, associated with given classes
# For each device, block in Unifi Controller, count the number of successful pings.
# The idea is that, during DDOS, all devices will timeout (0 successful pings) except for the malicious device

import os, pandas, sys, logging, logging.handlers, yaml, datetime, requests, copy, glob, math
import argparse, json, subprocess, platform
from unifiapi.api import controller, UnifiApiError

# 0.1 initial version, copy from guard.py

version = 0.1

parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest="command")

refresh_parser = subparser.add_parser("refresh", help="Refresh list of AP's")

ping_parser =  subparser.add_parser("ping", help="x.x.x.x : ping x.x.x.x")
ping_parser.add_argument("ip", help="IP address to ping")
ping_parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout")

client_parser = subparser.add_parser("client", help="Iterate over a klas(sen) and block/unblock students")
client_parser.add_argument("--klas", help="All klassen with this pattern will be considered")
client_parser.add_argument("--list", help="Yaml file with a list of klassen to be considered")
client_parser.add_argument("--timeout", type=int, default=1, help="Timeout per try")
client_parser.add_argument("--tries", type=int, default=25, help="Nbr of tries")

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

def init_api(site_code=None):
    ctrlr = controller()
    if not site_code:
        profile_config = {}
        for filename in ('unifiapi.yaml', os.path.expanduser('~/.unifiapi_yaml')):
            try:
                profile_config = yaml.safe_load(open(filename))["default"]
                break
            except:
                pass
        site_code = profile_config["site"]
    site = ctrlr.sites[site_code]()
    return site

def init_sdh():
    config = {}
    for filename in ('unifiapi.yaml', os.path.expanduser('~/.unifiapi_yaml')):
        try:
            config = yaml.safe_load(open(filename))["sdh"]
            break
        except:
            pass
    return config

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

if args.version:
    print(f"Current version is {version}")

def block_client(mac, block=True):
    try:
        if not ":" in mac:
            mac = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
        log.info(f"{"Block" if args.block else "Unblock"} Client {mac}")
        site = init_api()
        if block:
            site.c_block_client(**{"mac": mac})
        else:
            site.c_unblock_client(**{"mac": mac})
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.command == "client":
    try:
        if args.list:
            with open(args.list, "r") as jf:
                klas_list = yaml.load(jf, Loader=yaml.SafeLoader)
        elif args.klas:
            with open("ddos-klas-list.yaml", "r") as jf:
                klas_list = yaml.load(jf, Loader=yaml.SafeLoader)
                klas_list = [k for k in klas_list if args.klas in k]
        else:
            print("--klas of --list opgeven aub")
        log.info(f"Nbr of tries {args.tries}, Timeout {args.timeout}")
        log.info(f"Start with klassen: {klas_list}")

        with open("ddos-mac-list.yaml", "r") as yf:
            mac_list = yaml.load(yf, Loader=yaml.SafeLoader)
        klas2mac_addresses = {}
        for item in mac_list:
            if item["klascode"] in klas2mac_addresses:
                klas2mac_addresses[item["klascode"]].append(item)
            else:
                klas2mac_addresses[item["klascode"]] = [item]

        # Iterate over klas_list, find the students and mac addresses and iterate over the students
        site = init_api()
        nbr_clients = 0
        for klas in klas_list:
            mac_list = klas2mac_addresses[klas]
            for item in mac_list:
                # At this point, the DDOS is ongoing, so ping to 8.8.8.8 should timeout
                # Block the client, send 4 (defaulr) pings with 5sec (default) timeout.  Count and display the number of successful pings.  Unblock the client
                # The idea is that the number of successful pings is larger than 0 when the culprit is blocked
                nbr_pings_ok = 0
                mac = item["mac"]
                if not ":" in mac:
                    mac = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
                site.c_block_client(**{"mac": mac})
                for tries in range(args.tries):
                    if ping("8.8.8.8", args.timeout): nbr_pings_ok += 1
                log.info(f"Block {klas},{item["naam"]} {item["voornaam"]}, {mac}, pings({nbr_pings_ok})")
                site.c_unblock_client(**{"mac": mac})
                nbr_clients += 1
        log.info(f"End, nbr clients: {nbr_clients}")
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
    config = {}
    for filename in ('unifiapi.yaml', os.path.expanduser('~/.unifiapi_yaml')):
        try:
            config = yaml.safe_load(open(filename))["entra"]
            break
        except:
            pass
    return config

# From entra, get a list of devices and students.  Correlate and save as yaml file, with as parameters, name, class and device mac address
if args.command == "refresh":
    try:
        log.info("Start dumping student/mac address info into yaml file")
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
                        mac_list.append({
                            "klascode": student["klascode"],
                            "username": student["username"],
                            "naam": student["naam"],
                            "voornaam": student["voornaam"],
                            "mac": device["mac"]
                        })
                        klas_list.append(student["klascode"])
            else:
                log.error(f"could not get devices from Entra, {res['data']}")
        if mac_list:
            with open("ddos-mac-list.yaml", "w") as jf:
                yaml.dump(mac_list, jf)
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