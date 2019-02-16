from flask import request, Flask, make_response
import jwt
import requests
import time
import uuid
import os
import tempfile
import math
import struct
import re
from dotenv import load_dotenv

load_dotenv()

# Secrets
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
SECRET_KEY = os.environ['SECRET_KEY']
APP_TOKEN = os.environ['APP_TOKEN']

# Endpoints
OAUTH_URL = "https://slack.com/api/oauth.access"
POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"
EDIT_MESSAGE_URL = "https://slack.com/api/chat.update"
REDIRECT_URL = os.environ['REDIRECT_URL']
MOBILE_SCHEME = os.environ['MOBILE_SCHEME']

# Slack IDs
ADMIN_CHANNEL_ID = os.environ['ADMIN_CHANNEL_ID']
ADMIN_USERS = os.environ['ADMIN_USERS'].split(";")

# Globals
DOOR_STATUS = 0
LAST_USER_LOGINS = {}

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY


@app.route('/')
def index():
    return "These are not the doors you are looking for."

@app.route('/auth')
def auth():

    code = request.args.get("code", None)
    if not code:
        return "Invalid auth code.", 400

    data = { 'client_id': CLIENT_ID,
             'client_secret': CLIENT_SECRET,
             'code': code,
             'redirect_uri': REDIRECT_URL
    }

    response = make_response()
    slack_response = requests.post(OAUTH_URL, data=data)
    slack_response = slack_response.json()

    if 'error' in slack_response:
        error_msg = slack_response['error']
        response.headers['Location'] = f"{MOBILE_SCHEME}?error={error_msg}"
        return response, 302

    else:
        user_token = slack_response['access_token']
        user_id = slack_response['user']['id']

        message = { "user_token" : user_token, "id" : user_id }
        signed = jwt.encode(message, SECRET_KEY, "HS256").decode('utf-8')
        response.headers['Location'] = f"{MOBILE_SCHEME}?access_token={signed}"
        return response, 302

    # return "Unhandled Slack response", 400

@app.route('/door/request', methods=['POST'])
def door_request():

    authorization = request.headers.get('Authorization', None)
    if not authorization:
        return "Missing authorization.", 400

    parts = authorization.split(" ")

    if len(parts) != 2:
        return "Invalid bearer token.", 400

    jwt_token = parts[1]
    decoded = jwt.decode(jwt_token, SECRET_KEY, "HS256")
    user_id = decoded['id']
    user_token = decoded['user_token']

    if not user_token:
        return "Invalid auth token.", 401

    message = {
        "channel" : ADMIN_CHANNEL_ID,
        "text" : f"Request from <@{user_id}>",
        "attachments" : [
            {
                "text" : "Open the door for this user?",
                "color": "#3AA3E3",
                "callback_id" : "door_request_response",
                "attachment_Type" : "default",
                "actions" : [{
                    "name" : "response",
                    "text" : "Open",
                    "type" : "button",
                    "value" : "yes"
                },
                {
                    "name" : "response",
                    "text" : "Reject",
                    "type" : "button",
                    "value" : "no",
                    "style": "danger"
                }]
            }
        ]
    }

    headers = { "Authorization" : f"Bearer {APP_TOKEN}" }
    response = requests.post(POST_MESSAGE_URL, headers=headers, json=message)
    return "", 200

@app.route('/door/open', methods=['POST'])
def door_open():

    print(request.form['payload'])
    message = JSON.parse(request.form['payload'])

    try:
        callback_id = message['callback_id']
        user_id = message['user']['id']
        answer_is_yes = message['actions'][0]['value'] == "yes"
        message_timestamp = message['message_ts']
        requested_user = re.findall('Request from (.+)', message['original_message']['text'])[0]
    except:
        return "Invalid request.", 400

    print(message)
    if callback_id != "door_request_response" or user_id.upper() not in ADMIN_USERS:
        return "Ignoring...", 200

    headers = { "Authorization" : f"Bearer {APP_TOKEN}" }
    message = {
        "channel" : ADMIN_CHANNEL_ID,
        "ts" : message_timestamp
    }


    if answer_is_yes:
        text = f"Door opened by <@{user_id}> for <@requested_user>."
    else:
        text = f"<@{user_id}> rejected request from <@requested_user>."

    return text, 200
    # message['text'] = text
    # response = requests.post(POST_MESSAGE_URL, headers=headers, json=message)
    # return "Done", 200
    # print(response.text)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
