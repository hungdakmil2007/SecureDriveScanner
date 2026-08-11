# Author: Nguyen Hung Tran
# Final project - ITSC203

import os
import json
import urllib.request
import urllib.error


# Look up a SHA256 hash using the VirusTotal API
# Only the hash is sent, not the full file
def lookup_hash(file_hash):
    api_key = os.environ.get("VT_API_KEY")

    if api_key is None:
        return {
            "status": "API key missing",
            "malicious": 0,
            "suspicious": 0
        }

    url = (
        "https://www.virustotal.com/api/v3/files/"
        + file_hash
    )

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:
            response_data = response.read().decode("utf-8")
            data = json.loads(response_data)

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))

            return {
                "status": "Found",
                "malicious": malicious,
                "suspicious": suspicious
            }

    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {
                "status": "Hash not found",
                "malicious": 0,
                "suspicious": 0
            }

        elif error.code == 401:
            return {
                "status": "Invalid API key",
                "malicious": 0,
                "suspicious": 0
            }

        elif error.code == 429:
            return {
                "status": "API quota exceeded",
                "malicious": 0,
                "suspicious": 0
            }

        return {
            "status": "API error " + str(error.code),
            "malicious": 0,
            "suspicious": 0
        }

    except (urllib.error.URLError, TimeoutError):
        return {
            "status": "Connection error",
            "malicious": 0,
            "suspicious": 0
        }