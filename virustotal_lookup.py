# Author: Nguyen Hung Tran
# Final project - ITSC203

import os
import json
import urllib.request
import urllib.error


CACHE_FILE = "vt_cache.json"


# Load previous VirusTotal results from a local cache file
def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        # Course requirement - File handling:
        with open(CACHE_FILE, "r", encoding="utf-8") as cache_file:
            return json.load(cache_file)

    except (OSError, json.JSONDecodeError):
        return {}


# Save VirusTotal results to the local cache file
def save_cache(cache):
    try:
        # Course requirement - File handling:
        with open(CACHE_FILE, "w", encoding="utf-8") as cache_file:
            json.dump(
                cache,
                cache_file,
                indent=4
            )

    except OSError:
        pass


# Look up a SHA256 hash using VirusTotal
# Only the hash is sent, not the full file
def lookup_hash(file_hash):
    cache = load_cache()

    # Use a previous result without making another API request
    if file_hash in cache:
        cached_result = cache[file_hash]
        cached_result["source"] = "Cache"

        return cached_result

    api_key = os.environ.get("VT_API_KEY")

    if api_key is None:
        return {
            "status": "API key missing",
            "malicious": 0,
            "suspicious": 0,
            "source": "None"
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

            result = {
                "status": "Found",
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "source": "VirusTotal API"
            }

            # Save successful lookup for future scans
            cache[file_hash] = result.copy()
            cache[file_hash].pop("source", None)
            save_cache(cache)

            return result

    except urllib.error.HTTPError as error:
        if error.code == 404:
            result = {
                "status": "Hash not found",
                "malicious": 0,
                "suspicious": 0,
                "source": "VirusTotal API"
            }

            # Cache not-found hashes to avoid repeating requests
            cache[file_hash] = result.copy()
            cache[file_hash].pop("source", None)
            save_cache(cache)

            return result

        elif error.code == 401:
            return {
                "status": "Invalid API key",
                "malicious": 0,
                "suspicious": 0,
                "source": "VirusTotal API"
            }

        elif error.code == 429:
            return {
                "status": "API quota exceeded",
                "malicious": 0,
                "suspicious": 0,
                "source": "VirusTotal API"
            }

        return {
            "status": "API error " + str(error.code),
            "malicious": 0,
            "suspicious": 0,
            "source": "VirusTotal API"
        }

    except (urllib.error.URLError, TimeoutError):
        return {
            "status": "Connection error",
            "malicious": 0,
            "suspicious": 0,
            "source": "VirusTotal API"
        }