import requests
import json
import logging

log = logging.getLogger(__name__)


def get_remote_libc_with_leaks(symbols):
    """
    Expecting symbols like:
    symbols = {"symbols" :{
        "strncpy": "db0",
        "strcat": "0x000000000d800"
    }
    }
    """

    url = "https://libc.rip/api/find"
    headers = {"Content-Type": "application/json"}

    data = json.dumps(symbols)

    resp = requests.post(url, headers=headers, data=data)

    if resp.status_code != 200:
        log.error("Got response {} from {}".format(resp.status_code, url))
        return None

    resp_dict = json.loads(resp.content)
    log.info("Matched {} possible libc".format(len(resp_dict)))

    return resp_dict
