import requests
import json
import os
import base64

# Disable warnings for unverified HTTPS requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define common headers
common_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/json',
    'Referer': 'https://app.snapp.taxi/login',
    'Origin': 'https://app.snapp.taxi'
}

# Function to display the captcha image
def display_captcha(image_data):
    with open("captcha.jpg", "wb") as f:
        f.write(base64.b64decode(image_data.split(',')[1]))
    os.system("open captcha.jpg")  # Use "open" on macOS, "xdg-open" on Linux

# Step 1: Send GET request to the login URL
login_url = "https://app.snapp.taxi/login"
response = requests.get(login_url, headers=common_headers, verify=False)

if response.status_code == 200:
    cellphone = input("Please enter your phone number : ")

    # Step 2: Send POST request to the endpoint with required headers and JSON payload
    url = "https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp"
    headers = common_headers.copy()
    headers.update({
        "Cookie": "cookiesession1=678B286C29D1A87602E7354E18ADE9F2",
        "Locale": "fa-IR",
        "App-Version": "pwa",
        "X-App-Version": "v18.11.0",
        "X-App-Name": "passenger-pwa",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers"
    })

    # JSON payload
    data = {
        "cellphone": cellphone,
        "attestation": {
            "method": "skip",
            "platform": "skip"
        },
        "extra_methods": []
    }

    # Send the POST request
    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
    print("Initial login response:", response.text)

    # is false :  if response.status_code == 200 and response.json().get("status") == 2001
    if response.status_code != 400 or response.json().get("status") == 2001:
        print("Captcha is required.")
        captcha_url = "https://app.snapp.taxi/api/captcha/api/v1/generate/text/numeric/71C84A80-395B-448E-A240-B7DC939186D3"

        captcha_response = requests.get(captcha_url, headers=headers, verify=False)
        print("Captcha generation response:", captcha_response.text)

        if captcha_response.status_code == 200:
            captcha_data = captcha_response.json()
            captcha_image = captcha_data.get("image")
            ref_id = captcha_data.get("ref_id")

            # Display the captcha image
            display_captcha(captcha_image)

            # Prompt the user to solve the captcha
            captcha_solution = input("Please solve the captcha and enter the result: ")

            # Step 2: Send POST request to the login endpoint with captcha solution
            login_data = {
                "cellphone": cellphone,
                "attestation": {
                    "method": "numeric",
                    "platform": "captcha"
                },
                "extra_methods": [],
                "captcha": {
                    "client_id": "71C84A80-395B-448E-A240-B7DC939186D3",
                    "solution": captcha_solution,
                    "ref_id": ref_id,
                    "type": "numeric"
                }
            }
            login_response = requests.post(url, headers=headers, data=json.dumps(login_data), verify=False)
            print("Captcha verification response:", login_response.text)

            # Check if login is successful
            if login_response.status_code == 200:
                print("Captcha verified and login initiated.")
                otp_token = input("Please enter the OTP token you received: ")
                auth_url = "https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp/auth"

                # JSON payload with the user-provided phone number and OTP token
                data = {
                    "attestation": {
                        "method": "skip",
                        "platform": "skip"
                    },
                    "grant_type": "sms_v2",
                    "client_id": "ios_sadjfhasd9871231hfso234",
                    "client_secret": "23497shjlf982734-=1031nln",
                    "cellphone": cellphone,
                    "token": otp_token,
                    "referrer": "pwa",
                    "device_id": "93a4d99a-38c4-4eec-9382-158563122584"
                }

                # Send the POST request
                response = requests.post(auth_url, headers=headers, data=json.dumps(data), verify=False)
                print("OTP verification response:", response.text)

                # Check if the request is successful
                if response.status_code == 200:
                    print("Authentication successful")
                    response_data = response.json()
                    access_token = response_data.get('access_token')
                    print(f"Access Token: {access_token}")

                    # Step 4: Use the access token to get the user's balance
                    balance_url = "https://app.snapp.taxi/api/api-base/v2/passenger/balance"
                    balance_headers = headers.copy()
                    balance_headers.update({
                        "Authorization": f"Bearer {access_token}"
                    })

                    balance_data = {
                        "place": "sidemenu-topup"
                    }

                    balance_response = requests.post(balance_url, headers=balance_headers, data=json.dumps(balance_data), verify=False)
                    print("Balance retrieval response:", balance_response.text)

                    # Check if the request is successful
                    if balance_response.status_code == 200:
                        balance_info = balance_response.json()
                        user_balance = balance_info.get('data', {}).get('balance')
                        print(f"User balance: {user_balance}")
                    else:
                        print('Failed to retrieve balance')
                        print(f"Status code: {balance_response.status_code}")
                        print(balance_response.text)
                else:
                    print("Failed to authenticate")
                    print(f"Status code: {response.status_code}")
                    print(response.text)
            else:
                print("Failed to verify captcha and initiate login")
                print(f"Status code: {login_response.status_code}")
                print(login_response.text)
        else:
            print("Failed to generate captcha")
            print(f"Status code: {captcha_response.status_code}")
            print(captcha_response.text)
    else:
        print("Failed to initiate login or captcha not required")
        print(f"Status code: {response.status_code}")
        print(response.text)
else:
    print("Failed to load login page")
    print(f"Status code: {response.status_code}")
    print(response.text)