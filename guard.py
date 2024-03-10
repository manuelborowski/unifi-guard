import os, pandas, sys, logging, logging.handlers, yaml, datetime
import argparse, json
from unifiapi.api import controller, UnifiApiError

# 1.0 initial version
# 1.1 added overwrite parameter, so that it is possible to define groups and set parameters on group-level.  Take radio 6e into account

version = 1.1

parser = argparse.ArgumentParser()
parser.add_argument("--save", help="Create the excel file", action="store_true")
parser.add_argument("--live", help="Check if there are differences between the controller and excel file and update the controller if required", action="store_true")
parser.add_argument("--overwrite", help="Use overwrite.json to overwrite parameters of selected AP's", action="store_true")
parser.add_argument("--dryrun", help="Do not apply differences to the controller", action="store_true")
parser.add_argument("--dump", help="Dump the devices in a json file", action="store_true")
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


radio_params = [("channel", "auto", lambda x: x), ("ht", "",  lambda x: str(x)), ("tx_power_mode", "", lambda x: x), ("tx_power", "", lambda x: int(x)),
                                                                                  ("min_rssi_enabled", "", lambda x: x == 1.0), ("min_rssi", "", lambda x: int(x))]
radio_types = ["ng", "na", "6e"]

# from a list of devices, filter the uaps and from each uap retrieve only relevant info
def get_filtered_uaps(devices):
    try:
        filtered_devices = []
        for d in devices:
            if "UAP" in d["name"]:
                data ={"name": d["name"], "state": d["state"], "id": d["_id"]}
                for r in d["radio_table"]:
                    prefix = r["radio"]
                    for p in radio_params:
                        data[f"{prefix}_{p[0]}"] = r[p[0]] if p[0] in r else p[1]
                data.update({ "name": d["name"], "state": d["state"], "id": d["_id"]})
                filtered_devices.append(data)
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
        now = datetime.datetime.now().strftime("%Y%m%d%H%M")
        log.info(f"Start creating excel file, {now}")
        site = init_api()
        devices = get_devices(site)
        live_uaps = get_filtered_uaps(devices)
        data_frame = pandas.DataFrame(data=live_uaps)
        data_frame.to_excel(f"uap_devices-{now}.xlsx", index=False)
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
        converters = {}
        for rp in radio_params:
            for rt in radio_types:
                converters[f"{rt}_{rp[0]}"] = rp[2]
        data_frame = pandas.read_excel("uap_devices.xlsx", converters=converters)
        saved_uaps = data_frame.to_dict(orient="records")
        saved_uap_cache = {u["id"]: u for u in saved_uaps}
        log.info(f"Retreived {len(saved_uaps)} from excel file")
        # for all saved UAPs, check if there are differences with the live UAPs.  If so, store for later processing
        overwrite_uaps = {}
        if args.overwrite:
            log.info("Using info in overwrite.json")
            with open("overwrite.json", "r") as overwrite_file:
                overwrite_data = json.load(overwrite_file)
                uap_to_group = {}
                for g in overwrite_data["groups"]:
                    for uap in g["items"]:
                        if uap in uap_to_group:
                            uap_to_group[uap].append(g["tag"])
                        else:
                            uap_to_group[uap] = [g["tag"]]
                if uap_to_group:
                    overwrite_uaps["uaps"] = uap_to_group
                    overwrite_uaps["settings"] = overwrite_data["settings"]

        update_uaps = {}
        nbr_not_live_uaps = 0
        for saved_uap in saved_uaps:
            if not saved_uap["state"]:
                log.info(f"UAP {saved_uap['name']} is disabled, skip...")
                continue
            if saved_uap["id"] in live_uap_cache:
                live_uap = live_uap_cache[saved_uap["id"]]
                keys = list(saved_uap.keys())

                for rt in radio_types:
                    if saved_uap[f"{rt}_tx_power_mode"] != "custom":
                        keys.remove(f"{rt}_tx_power")
                    if not saved_uap[f"{rt}_min_rssi_enabled"]:
                        keys.remove(f"{rt}_min_rssi")
                if overwrite_uaps and saved_uap["name"] in overwrite_uaps["uaps"]:
                    for g in overwrite_uaps["uaps"][saved_uap["name"]]:
                        for s in overwrite_uaps["settings"][g]:
                            if s["active"]:
                                saved_uap[s["setting"]] = s["value"]
                for key in keys:
                    if key in live_uap and str(saved_uap[key]) != str(live_uap[key]):
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
                radio = {}

                for uap_radio in uap_radio_table:
                    radio[uap_radio["radio"]] = uap_radio
                for k, v in update_radio.items():
                    if k[:2] in radio:
                        [radio_band, parameter] = [k[:2], k[3::]]
                        radio[radio_band][parameter] = v
                id_and_radio[id] = uap_radio_table
            if id_and_radio:
                for id, radio_table in id_and_radio.items():
                    try:
                        if args.dryrun:
                            log.info(f"Update UAP {live_uap_cache[id]['name']}, {radio_table}")
                        else:
                            result = site.put_device(id, radio_table=radio_table)
                            if not result.is_ok:
                                log.warning(f"Could not update UAP {device_cache[id]['name']}")
                    except UnifiApiError as e:
                        log.warning(f"Could not update UAP {device_cache[id]['name']}, {str(e)}")
        log.info(f"Done updating, {len(live_uaps)} UAPs")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')


