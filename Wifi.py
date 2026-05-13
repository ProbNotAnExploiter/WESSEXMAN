import requests
from osint import *


def read_config():
    """Loads the configuration data from config.yaml file.

    Returns:
        dict: A dictionary containing the configuration data.
    """
    try:
        # Open the config.yaml file in read mode
        with open("Utilities/config.yaml", "r") as config_file:
            # Parse the contents of the file into a dictionary
            parsed_config = yaml.safe_load(config_file)
            return parsed_config
    except FileNotFoundError:
        # Return an error message if the file is not found
        return {"error": "config.yaml file not found"}
    except yaml.YAMLError:
        # Return an error message if there is an error parsing the file
        return {"error": "Error parsing config.yaml file"}


def wigle_ssid(ssid_param):
    config = read_config()
    api_key = config.get("wigle_auth")

    if not api_key:
        return err(f"can't locate api key")

    headers = {"Accept": "application/json", "Authorization": f"Basic {api_key}"}

    params = {"ssid": ssid_param}

    try:
        response = requests.get(
            "https://api.wigle.net/api/v2/network/search",
            headers=headers,
            params=params,
            timeout=10,
            verify=not config.get("no-ssl-verify", False),
        )

        data = response.json()

        if not data.get("success"):
            return [{"module": "wigle", "error": data.get("message", "Request failed")}]

        results = data.get("results", [])
        if not results:
            return [{"module": "wigle", "error": "No results found"}]

        return [
            {
                "module": "wigle",
                "ssid": item.get("ssid"),
                "bssid": item.get("netid"),
                "latitude": item.get("trilat"),
                "longitude": item.get("trilong"),
            }
            for item in results
        ]

    except requests.RequestException as e:
        return [{"module": "wigle", "error": f"Network error: {str(e)}"}]
    except ValueError:
        return [{"module": "wigle", "error": "Invalid JSON response"}]
