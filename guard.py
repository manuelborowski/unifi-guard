import os, pandas, sys, logging, logging.handlers, yaml
import argparse, json
from unifiapi.api import controller, UnifiApiError

# 1.0 initial version

version = 1.0

parser = argparse.ArgumentParser()
parser.add_argument("--save", help="Create the excel file", action="store_true")
parser.add_argument("--live", help="Check if there are differences between the controller and excel file and update the controller if required", action="store_true")
parser.add_argument("--dump", help="Dump the devices in a json file", action="store_true")
parser.add_argument("--dryrun", help="Do not apply differences to the controller", action="store_true")
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


# from a list of devices, filter the uaps and from each uap retreive only relevant info
def get_filtered_uaps(devices):
    try:
        filtered_devices = []
        for d in devices:
            if "UAP" in d["name"]:
                if d["radio_table"][0]["radio"] == "ng":
                    radio_2 = d["radio_table"][0]
                    radio_5 = d["radio_table"][1]
                else:
                    radio_2 = d["radio_table"][1]
                    radio_5 = d["radio_table"][0]
                filtered_devices.append({
                    "name": d["name"],
                    "state": d["state"],
                    "2_channel": radio_2["channel"],
                    "2_ht": radio_2["ht"],
                    "2_tx_power_mode": radio_2["tx_power_mode"] if "tx_power_mode" in radio_2 else '',
                    "2_tx_power": radio_2["tx_power"] if "tx_power" in radio_2 else '',
                    "2_min_rssi_enabled": radio_2["min_rssi_enabled"] if "min_rssi_enabled" in radio_2 else '',
                    "2_min_rssi": radio_2["min_rssi"] if "min_rssi" in radio_2 else '',
                    "5_channel": radio_5["channel"],
                    "5_ht": radio_5["ht"],
                    "5_tx_power_mode": radio_5["tx_power_mode"] if "tx_power_mode" in radio_5 else '',
                    "5_tx_power": radio_5["tx_power"] if "tx_power" in radio_5 else '',
                    "5_min_rssi_enabled": radio_5["min_rssi_enabled"] if "min_rssi_enabled" in radio_5 else '',
                    "5_min_rssi": radio_5["min_rssi"] if "min_rssi" in radio_5 else '',
                    "id": d["_id"],
                })
        log.info(f"Retreived {len(filtered_devices)} UAPS from UNIFI controller")
        return filtered_devices
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e

if args.version:
    print(f"Current version is {version}")


# Dump the devices in a json file
if args.dump:
    try:
        log.info("Start dumping into json file")
        site = init_api()
        devices = get_devices(site)
        flat_list = [d.data for d in devices]
        with open("devices.json", "w") as jf:
            json.dump(flat_list, jf)
        log.info(f"Done dumping devices to json file, {len(flat_list)} devices")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


# Get the device-configurations and store in a excel file
if args.save:
    try:
        log.info("Start creating excel file")
        site = init_api()
        devices = get_devices(site)
        live_uaps = get_filtered_uaps(devices)
        data_frame = pandas.DataFrame(data=live_uaps)
        data_frame.to_excel("uap_devices.xlsx", index=False)
        log.info(f"Done creating excel file, {len(live_uaps)} UAPs")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


#Get the device-configurations, compare with the stored excel file and update when there is a difference
# --dryrun: if true, log the differences, do not update
if args.live:
    try:
        log.info("Start updating")
        site = init_api()
        devices = get_devices(site)
        live_uaps = get_filtered_uaps(devices)
        live_uap_cache = {u["id"]: u for u in live_uaps}
        data_frame = pandas.read_excel("uap_devices.xlsx",
                                       converters={"2_min_rssi_enabled": lambda x: x == 1.0, "5_min_rssi_enabled": lambda x: x == 1.0, "2_ht": lambda x: str(x),
                                                   "5_ht": lambda x: str(x), "2_tx_power": lambda x: int(x), "5_tx_power": lambda x: int(x),
                                                   "2_min_rssi": lambda x: int(x), "5_min_rssi": lambda x: int(x), "state": lambda x: x == 1
                                                   })
        saved_uaps = data_frame.to_dict(orient="records")
        saved_uap_cache = {u["id"]: u for u in saved_uaps}
        log.info(f"Retreived {len(saved_uaps)} from excel file")
        # for all saved UAPs, check if there are differences with the live UAPs.  If so, store for later processing
        update_uaps = {}
        nbr_not_live_uaps = 0
        for saved_uap in saved_uaps:
            if not saved_uap["state"]:
                log.info(f"UAP {saved_uap['name']} is disabled, skip...")
                continue
            if saved_uap["id"] in live_uap_cache:
                live_uap = live_uap_cache[saved_uap["id"]]
                keys = list(saved_uap.keys())
                if saved_uap["2_tx_power_mode"] != "custom":
                    keys.remove("2_tx_power")
                if not saved_uap["2_min_rssi_enabled"]:
                    keys.remove("2_min_rssi")
                if saved_uap["5_tx_power_mode"] != "custom":
                    keys.remove("5_tx_power")
                if not saved_uap["5_min_rssi_enabled"]:
                    keys.remove("5_min_rssi")
                for key in keys:
                    if saved_uap[key] != live_uap[key]:
                        log.info(f"Difference in UAP settings, UAP {saved_uap['name']}, KEY {key}, SAVED {saved_uap[key]}, LIVE {live_uap[key]}")
                        if saved_uap["id"] in update_uaps:
                            update_uaps[saved_uap["id"]][key] = saved_uap[key]
                        else:
                            update_uaps[saved_uap["id"]] = {key: saved_uap[key]}
            else:
                log.warning(f"Saved UAP {saved_uap['name']} not found in LIVE UAP cache")
                nbr_not_live_uaps += 1
        if nbr_not_live_uaps > 0:
            log.warning(f"Warning, there are {nbr_not_live_uaps} saved UAPs that are NOT LIVE")
        # for all live UAPs, check if there are unsaved UAPs
        nbr_unsaved_uap = 0
        for live_uap in live_uaps:
            if live_uap["id"] not in saved_uap_cache:
                log.warning(f"Warning, LIVE UAP {live_uap['name']} is NOT saved")
                nbr_unsaved_uap += 1
        if nbr_unsaved_uap > 0:
            log.warning(f"Warning, there are {nbr_unsaved_uap} UNSAVED UAPs")
        if update_uaps:
            log.info("Start update LIVE UAPs")
            device_cache = {d["_id"]: d for d in devices}
            id_and_radio = {}
            for id, update_radio in update_uaps.items():
                uap_radio_table = device_cache[id]["radio_table"]
                if uap_radio_table[0]["radio"] == "ng":
                    radio = {"2": uap_radio_table[0], "5": uap_radio_table[1]}
                else:
                    radio = {"2": uap_radio_table[1], "5": uap_radio_table[0]}
                for k, v in update_radio.items():
                    if k[0] in radio:
                        [radio_band, parameter] = [k[0], k[2::]]
                        radio[radio_band][parameter] = v
                id_and_radio[id] = uap_radio_table
            if not args.dryrun and id_and_radio:
                for id, radio_table in id_and_radio.items():
                    try:
                        result = site.put_device(id, radio_table=radio_table)
                        if not result.is_ok:
                            log.warning(f"Could not update UAP {device_cache[id]['name']}")
                    except UnifiApiError as e:
                        log.warning(f"Could not update UAP {device_cache[id]['name']}, {str(e)}")
        log.info(f"Done updating, {len(live_uaps)} UAPs")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


