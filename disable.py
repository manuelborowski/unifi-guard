# Disable/enable AP's, matching the given name
# M208 : AP in M208 only
# M2 : all AP's of the second floor in block M
# M : all AP's in block M

import os, pandas, sys, logging, logging.handlers, yaml, datetime, requests, copy, glob, math
import argparse, json
from unifiapi.api import controller, UnifiApiError

# 0.1 initial version, copy from guard.py

version = 0.1

parser = argparse.ArgumentParser()
parser.add_argument("--refresh", help="Refresh list of AP's", action="store_true")
parser.add_argument("--dryrun", help="Do not update controller, log actions", action="store_true")
parser.add_argument("--version", help="Return version", action="store_true")
parser.add_argument("--disable", help="xxx : disable AP's matching name xxx")
parser.add_argument("--enable", help="xxx : disable AP's matching name xxx")
parser.add_argument("--block", help="xxx : block client mith MAC xxx")
parser.add_argument("--unblock", help="xxx : unblock client mith MAC xxx")

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

# get all clients from the controller
def get_clients(site):
    try:
        clients = site.active_clients()
        log.info(f"Retreived {len(clients)} clients from UNIFI controller")
        return clients
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e

radio_params = [("channel", "auto", lambda x: x), ("ht", "",  lambda x: str(x)), ("tx_power_mode", "", lambda x: x), ("tx_power", "", lambda x: int(x)),
                                                                                  ("min_rssi_enabled", "", lambda x: x == 1.0), ("min_rssi", "", lambda x: int(x))]
radio_types = ["ng", "na", "6e"]

# from a list of devices, filter the uaps and from each uap retrieve only relevant info
def get_filtered_uaps(devices):
    try:
        filtered_devices = []
        for d in devices:
            if "UAP" in d["name"]:
                data ={"name": d["name"], "state": d["state"], "id": d["_id"], "mac": d["mac"], "model": d["model"]}
                for r in d["radio_table"]:
                    prefix = r["radio"]
                    for p in radio_params:
                        data[f"{prefix}_{p[0]}"] = r[p[0]] if p[0] in r else p[1]
                filtered_devices.append(data)
        log.info(f"Retreived {len(filtered_devices)} UAPS from UNIFI controller")
        return filtered_devices
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e

if args.version:
    print(f"Current version is {version}")

if args.block or args.unblock:
    try:
        mac = args.block if args.block else args.unblock
        if not ":" in mac:
            mac = mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
        log.info(f"{"Block" if args.block else "Unblock"} Client {mac}")
        site = init_api()
        if args.block:
            site.c_block_client(**{"mac": mac})
        else:
            site.c_unblock_client(**{"mac": mac})
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

if args.disable or args.enable:
    try:
        mac = args.disable if args.disable else args.enable
        log.info(f"{"Disable" if args.disable else "Enable"} AP's")
        site = init_api()
        devices = []
        with open("disable-devices.yaml", "r") as jf:
            all_devices = yaml.load(jf, Loader=yaml.SafeLoader)
            for d in all_devices:
                if mac in d["name"]:
                    devices.append(d)
        for d in devices:
            log.info(f"{"Disable" if args.disable else "Enable"} {d["name"]}")
            site.put_device(d["id"], **{"disabled": args.disable is not None})

    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')

# Dump the devices in a yaml file
if args.refresh:
    try:
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
        with open("disable-devices.yaml", "w") as jf:
            yaml.dump(flat_list, jf)
        log.info(f"Done dumping devices to yaml file, {len(flat_list)} devices")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')