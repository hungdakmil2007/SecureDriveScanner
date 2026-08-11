# Author: Nguyen Hung Tran
# Final project - ITSC203

import os
import json
import urllib.request
import urllib.error


CACHE_FILE = "vt_cache.json"
# Limit new VirusTotal API requests during one scan
MAX_VT_LOOKUPS = 3


#load previous Virustotal results from a local cache file
def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        # Course requirement - File handling:
        with open(CACHE_FILE, "r", encoding="utf-8") as cache_file:
            return json.load(cache_file)

    except (OSError, json.JSONDecodeError):
        return {}


#save VirusTotal results to the local cache file
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

#check whether a hash already has a cached Virustotal result
def get_cached_result(file_hash):
    cache = load_cache()

    if file_hash not in cache:
        return None

    result = cache[file_hash].copy()
    result["source"] = "Cache"

    return result

# Look up a SHA256 hash using VirusTotal
#only the hash is sent, not the full file
def lookup_hash(file_hash):
    cache = load_cache()

    #use a previous result without making another API request
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

            #save successful lookup for future scans
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

            #cache not found hashes to avoid repeating requests
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

# Check suspicious file hashes with VirusTotal
# Cached results don't count toward the API request limit
def lookup_hash_results(hash_results):
    api_requests = 0
    stop_reason = None

    for hash_result in hash_results:
        file_hash = hash_result["sha256"]

        #always check the local cache first
        cached_result = get_cached_result(file_hash)

        if cached_result is not None:
            hash_result["vt_status"] = cached_result["status"]
            hash_result["vt_malicious"] = cached_result["malicious"]
            hash_result["vt_suspicious"] = cached_result["suspicious"]
            hash_result["vt_source"] = cached_result["source"]
            continue

        #stop new API requests after a serious API problem
        if stop_reason is not None:
            hash_result["vt_status"] = "Not checked - " + stop_reason
            hash_result["vt_malicious"] = 0
            hash_result["vt_suspicious"] = 0
            hash_result["vt_source"] = "None"
            continue

        #limit new Virustotal requests during this scan
        if api_requests >= MAX_VT_LOOKUPS:
            hash_result["vt_status"] = (
                "Not checked - scan lookup limit reached"
            )
            hash_result["vt_malicious"] = 0
            hash_result["vt_suspicious"] = 0
            hash_result["vt_source"] = "None"
            continue

        result = lookup_hash(file_hash)

        #count only a real API request
        if result["source"] == "VirusTotal API":
            api_requests += 1

        hash_result["vt_status"] = result["status"]
        hash_result["vt_malicious"] = result["malicious"]
        hash_result["vt_suspicious"] = result["suspicious"]
        hash_result["vt_source"] = result["source"]

        # Stop unnecessary requests after these errors
        if result["status"] == "API quota exceeded":
            stop_reason = "API quota exceeded"

        elif result["status"] == "Invalid API key":
            stop_reason = "invalid API key"

        elif result["status"] == "API key missing":
            stop_reason = "API key missing"

        elif result["status"] == "Connection error":
            stop_reason = "connection error"

    return hash_results