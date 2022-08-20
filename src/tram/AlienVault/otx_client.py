import argparse
import hashlib
from warnings import catch_warnings

from OTXv2 import IndicatorTypes, OTXv2

## pip install OTXv2

# Your API key
API_KEY = ""
OTX_SERVER = "https://otx.alienvault.com/"

otx = OTXv2(API_KEY, server=OTX_SERVER)

# Get a nested key from a dict, without having to do loads of ifs
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:
        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results


def get_alerts(indicator_details):
    alerts = []

    # Return nothing if it's in the whitelist
    validation = getValue(indicator_details, ["validation"])
    if not validation:
        pulses = getValue(indicator_details, ["pulse_info", "pulses"])
        if pulses:
            for pulse in pulses:
                if "name" in pulse:
                    alerts.append("In pulse: " + pulse["name"])

    return alerts


def get_ip_alerts(ip):
    import re

    if re.findall(
        "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)",
        ip,
    ):
        return 0, []

    alerts = []
    try:
        indicator_details = otx.get_indicator_details_by_section(
            IndicatorTypes.IPv4, ip, "general"
        )

        # Return nothing if it's in the whitelist
        validation = getValue(indicator_details, ["validation"])
        if not validation:
            alerts = get_alerts(indicator_details)
            if len(alerts) > 0:
                return 1, indicator_details
            else:
                return 2, []
        else:
            return 3, validation
    except:
        return -1, []


def get_host_alerts(host):
    alerts = []
    try:
        indicator_details1 = otx.get_indicator_details_by_section(
            IndicatorTypes.HOSTNAME, host, "general"
        )
        indicator_details2 = otx.get_indicator_details_by_section(
            IndicatorTypes.DOMAIN, host, "general"
        )

        validation1 = getValue(indicator_details1, ["validation"])
        validation2 = getValue(indicator_details2, ["validation"])

        if not validation1 and not validation2:
            alerts.append(get_alerts(indicator_details1))
            alerts.append(get_alerts(indicator_details2))
            indicator_details1["pulse_info"]["pulses"] = (
                indicator_details1["pulse_info"]["pulses"]
                + indicator_details2["pulse_info"]["pulses"]
            )
            if len(alerts) > 0:
                return 1, indicator_details1

            else:
                return 2, []

        else:
            return 3, validation1 + validation2
    except:
        return -1, []


def get_url_alerts(url):
    alerts = []

    try:
        indicator_details = otx.get_indicator_details_by_section(
            IndicatorTypes.URL, url, "general"
        )

        validation = getValue(indicator_details, ["validation"])
        if not validation:
            alerts = get_alerts(indicator_details)
            if len(alerts) > 0:
                return 1, indicator_details
            else:
                return 2, []
        else:
            return 3, validation
    except:
        return -1, []


def get_hash_alerts(hash):
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    elif len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1
    elif len(hash) == 32:
        hash_type = IndicatorTypes.FILE_HASH_MD5
    else:
        return -1, []

    alerts = []
    try:
        indicator_details = otx.get_indicator_details_by_section(
            hash_type, hash, "general"
        )

        # Return nothing if it's in the whitelist
        validation = getValue(indicator_details, ["validation"])
        if not validation:
            alerts = get_alerts(indicator_details)
            if len(alerts) > 0:
                return 1, indicator_details
            else:
                return 2, []
        else:
            return 3, validation
    except:
        return -1, []
