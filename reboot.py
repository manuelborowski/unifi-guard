import os, sys, logging.handlers, yaml, argparse, json, subprocess

# 0 1 * * * cd /home/ict/unifi-guard/; /home/ict/unifi-guard/venv/bin/python3 /home/ict/unifi-guard/guard.py --dump
# 5 1 * * * cd /home/ict/unifi-guard/; /home/ict/unifi-guard/venv/bin/python3 /home/ict/unifi-guard/reboot.py --force

# 1.0 initial version
# 1.1 get list of devices from yaml


version = 1.1

parser = argparse.ArgumentParser()
parser.add_argument("--reboot", help="Reboot the AP.  If not specified, return the date", action="store_true")
parser.add_argument("--force", help="Force SSH to accept key", action="store_true")
parser.add_argument("--version", help="Return version", action="store_true")
args = parser.parse_args()

log = logging.getLogger("reboot")
LOG_FILENAME = os.path.join(sys.path[0], f'log/unifi-reboot.txt')
log.setLevel("INFO")
log_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1024 * 1024, backupCount=20)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

def init_config():
    config = {}
    for filename in ('unifiapi.yaml', os.path.expanduser('~/.unifiapi_yaml')):
        try:
            config = yaml.safe_load(open(filename))["reboot"]
            break
        except:
            pass
    return config


def start():
    try:
        config = init_config()
        devices = json.load(open(os.path.expanduser(config["json"])))
        command = "reboot" if args.reboot else "date"
        optional = "-o StrictHostKeychecking=no" if args.force else ""
        log.info(f"SSH command: sshpass -p xxx ssh {config['login']}@yyyy {optional} {command}")
        for device in devices:
            if device["model"] in config["types"]:
                output = subprocess.Popen(f"ping -w 2 -c 1 {device['ip']}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
                out_string = output[0].decode("utf-8")[:-1]
                if "1 received" in out_string:
                    output = subprocess.Popen(f"sshpass -p {config['password']} ssh {config['login']}@{device['ip']} {optional} date", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
                    out_string = output[0].decode("utf-8")[:-1]
                    if out_string != "":
                        output = subprocess.Popen(f"sshpass -p {config['password']} ssh {config['login']}@{device['ip']} {command}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
                        out_string = output[0].decode("utf-8")[:-1]
                        if out_string == "":
                            log.info(f'{device["name"]}, {device["ip"]} returned empty output.  OK when rebooting...')
                        else:
                            log.info(f'{device["name"]}, {device["ip"]} returned  {output[0].decode("utf-8")[:-1]}')
                    else:
                        log.error(f"{device['name']}, {device['ip']}, is NOT accessible (ping is OK, but cannot SSH.  Run once with --force)")
                else:
                    log.error(f"{device['name']}, {device['ip']}, is NOT alive")
        log.info(f"-- END ---")
    except Exception as e:
        log.error(f'{sys._getframe().f_code.co_name}: {e}')
        raise e

if args.version:
    print(f"Current version is {version}")
else:
    start()