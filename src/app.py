import requests
import jsonschema
import random
import os
from flask import Flask, jsonify, request, json
from jsonschema import validate
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

app = Flask('rest-api-widevine')

@app.route('/key', methods=['POST'])

def key():
  if request.is_json:
    data = json.loads(request.data)
    validation_result = validate_json_request(data)
    if validation_result is True:
        if "wvdId" not in data:
            data['wvdId'] = random.choice(wvd_provisions)['id']
        keys = get_decryption_keys(data['pssh'], data['licenseUrl'], data['headers'], data['wvdId'])
        return keys
    else:
        return {
            "error": True,
            "errorType": "validation",
            "message": validation_result
        }, 400
  else:
    return 'Content type is not supported.';
 
def validate_json_request(data):
    try:
        validate(instance=data, schema=request_schema)
    except jsonschema.exceptions.ValidationError as err:
        return err.message
    return True
    
def get_decryption_keys(_pssh, license_url, _headers, wvd_id):
    try:
        wvd_data = next(wvd for wvd in wvd_provisions if wvd["id"] == wvd_id)
        pssh = PSSH(_pssh)
        device = Device.load(os.path.dirname(os.path.dirname( __file__ )) + "/wvd/" + wvd_data['file'])
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, pssh)
        licence = requests.post(license_url, data=challenge, headers=_headers)
        licence.raise_for_status()
        cdm.parse_license(session_id, licence.content)
        keys = [];
        for key in cdm.get_keys(session_id):
            if key.type != 'SIGNING':
                keys.append({
                    "type": key.type,
                    "kid": key.kid.hex,
                    "key": key.key.hex(),
                })
        cdm.close(session_id)
        return {
            "data" : keys,
            "info" : {
                'securityLevel': wvd_data['security_level'],
                'wvd_id': wvd_data['id']
            }
        }
    except Exception as exception:
        pywidevine_exception = [
            "TooManySessions", 
            "InvalidSession", 
            "InvalidLicenseType", 
            "SignatureMismatch", 
            "InvalidInitData", 
            "InvalidLicenseMessage", 
            "NoKeysLoaded", 
            "InvalidContext",
            "HTTPError"
        ]
        if format(type(exception).__name__) in pywidevine_exception: 
            return {
                "error": True,
                "errorType": "cdm",
                "message": format(exception),
            }, 400
        else: 
            print(exception)
            return {
                "error": True,
                "errorType": "other",
                "message": 'Something went wrong.',
            }, 400
            
wvd_provisions = [
        {
            "id": 1,
            "security_level": "l3",
            "file": "google_android_sdk_built_for_x86_v4.1.0-android_3d713d77_4464_l3.wvd",
        }
    ]
    
request_schema = {
    "type": "object",
    "properties": {
        "pssh": {"type": "string"},
        "licenseUrl": {"type": "string"},
        "provider": {
            "type": "string",
            "enum": ["hbm"]
        },
        "headers": {
            "type": "object", 
            "properties": {
                "authorization": {
                    "type": "string"
                }
            },
            "required": ["authorization"],
            "additionalProperties": True
        }, 
        "wvdId": {
            "type": "integer",
            "minimum": 1,
            "maximum": len(wvd_provisions),
        }
    },
    "required": ["pssh", "licenseUrl", "provider", "headers"],
    "additionalProperties": False
}