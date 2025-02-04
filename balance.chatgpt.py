import requests
import re
from bs4 import BeautifulSoup
import urllib3
import sys
from PIL import Image
from io import BytesIO

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Content-Type': 'application/json',
    'Referer': 'https://app.snapp.taxi/login',
    'Origin': 'https://app.snapp.taxi'
}

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}

# Input phone number as user
phone_number = input("[+]Enter your phone number: ")

# Send phone number to receive OTP
print(f"[+]Making OTP code for: {phone_number}")
login_data = {
    "cellphone": phone_number,
    "attestation": {"method": "skip", "platform": "skip"},
    "extra_methods": []
}
r = requests.session()
otp_response = r.post('https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp', json=login_data, headers=headers, proxies=proxies, verify=False)
print(otp_response.text)

# بررسی پاسخ OTP
if otp_response.status_code == 200:
    otp_response_data = otp_response.json()
    if otp_response_data.get('captcha_type') == 'image':
        print("[+] Captcha image detected.")
        captcha_url = otp_response_data.get('captcha_url')
        
        # دانلود تصویر کپچا
        captcha_image_response = r.get(captcha_url, headers=headers, verify=False)
        if captcha_image_response.status_code == 200:
            # نمایش تصویر کپچا
            image = Image.open(BytesIO(captcha_image_response.content))
            image.show()

            # دریافت مقدار عددی کپچا از کاربر
            captcha_value = input("[+] Enter the captcha value: ")
            login_data["captcha"] = {"type": "image", "value": captcha_value}
            
            # ارسال دوباره درخواست OTP با کپچا
            otp_response = r.post(
                'https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp',
                json=login_data,
                headers=headers,
                proxies=proxies,
                verify=False
            )
            
            if otp_response.status_code == 200:
                print("[+] OTP sent successfully.")
                otp_response_data = otp_response.json()
                if otp_response_data.get('captcha_type') == 'none':
                    otp = input("[+]Enter the OTP: ")
                    
                    # Verify OTP to get authentication token
                    verify_data = {
                        "attestation": {"method": "skip", "platform": "skip"},
                        "grant_type": "sms_v2",
                        "client_id": "ios_sadjfhasd9871231hfso234",
                        "client_secret": "23497shjlf982734-=1031nln",
                        "cellphone": phone_number,
                        "token": otp,
                        "referrer": "pwa",
                        "device_id": "93a4d99a-38c4-4eec-9382-158563122584"
                    }
                    token_response = r.post('https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp/auth', json=verify_data, headers=headers, proxies=proxies, verify=False)
                    
                    if token_response.status_code == 200:
                        token_data = token_response.json()
                        access_token = token_data.get('access_token')
                        print(f"[+]Authentication token: {access_token}")
                        
                        # Send request to /api/api-base/v2/passenger/balance
                        balance_data = {
                            "place": "sidemenu-topup"
                        }
                        balance_headers = {
                            "Authorization": f"Bearer {access_token}",
                            "Content-Type": "application/json",
                            "User-Agent": headers['User-Agent'],
                            'Cookie': 'cookiesession1=678B286C29D1A87602E7354E18ADE9F2; _ga_Y4QV007ERR=GS1.1.1734963808.8.1.1734964455.34.0.0; _ga=GA1.1.2013732041.1732458988; _ym_uid=1732458988792538382; _ym_d=1732458988; _ym_isad=1; _clck=2fvf85%7C2%7Cfry%7C0%7C1818; _clsk=16026nd%7C1734963797740%7C1%7C0%7Cp.clarity.ms%2Fcollect'
                        }
                        balance_response = r.post('https://app.snapp.taxi/api/api-base/v2/passenger/balance', json=balance_data, headers=balance_headers, proxies=proxies, verify=False)
                        
                        if balance_response.status_code == 200:
                            print("[+]Balance request successful")
                            balance_data = balance_response.json()
                            balance = balance_data.get('data', {}).get('balance', 0)
                            print(f"Your balance is: {balance}")
                        else:
                            print(f"Failed to send balance request, status code: {balance_response.status_code}")
                    else:
                        print(f"Failed to verify OTP, status code: {token_response.status_code}")
                else:
                    print("[+]Captcha required")
                    captcha = input("[+]Enter the captcha: ")
                    login_data["captcha"] = captcha
                    otp_response = r.post('https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp', json=login_data, headers=headers, proxies=proxies, verify=False)
                    
                    if otp_response.status_code == 200:
                        print("[+]OTP sent successfully")
                        otp = input("[+]Enter the OTP: ")
                        
                        # Verify OTP to get authentication token
                        verify_data = {
                            "attestation": {"method": "skip", "platform": "skip"},
                            "grant_type": "sms_v2",
                            "client_id": "ios_sadjfhasd9871231hfso234",
                            "client_secret": "23497shjlf982734-=1031nln",
                            "cellphone": phone_number,
                            "token": otp,
                            "referrer": "pwa",
                            "device_id": "93a4d99a-38c4-4eec-9382-158563122584"
                        }
                        token_response = r.post('https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp/auth', json=verify_data, headers=headers, proxies=proxies, verify=False)
                        
                        if token_response.status_code == 200:
                            token_data = token_response.json()
                            access_token = token_data.get('access_token')
                            print(f"[+]Authentication token: {access_token}")
                            
                            # Send request to /api/api-base/v2/passenger/balance
                            balance_data = {
                                "place": "sidemenu-topup"
                            }
                            balance_headers = {
                                "Authorization": f"Bearer {access_token}",
                                "Content-Type": "application/json",
                                "User-Agent": headers['User-Agent'],
                                'Cookie': 'cookiesession1=678B286C29D1A87602E7354E18ADE9F2; _ga_Y4QV007ERR=GS1.1.1734963808.8.1.1734964455.34.0.0; _ga=GA1.1.2013732041.1732458988; _ym_uid=1732458988792538382; _ym_d=1732458988; _ym_isad=1; _clck=2fvf85%7C2%7Cfry%7C0%7C1818; _clsk=16026nd%7C1734963797740%7C1%7C0%7Cp.clarity.ms%2Fcollect'
                            }
                            balance_response = r.post('https://app.snapp.taxi/api/api-base/v2/passenger/balance', json=balance_data, headers=balance_headers, proxies=proxies, verify=False)
                            
                            if balance_response.status_code == 200:
                                print("[+]Balance request successful")
                                balance_data = balance_response.json()
                                balance = balance_data.get('data', {}).get('balance', 0)
                                print(f"Your balance is: {balance}")
                            else:
                                print(f"Failed to send balance request, status code: {balance_response.status_code}")
                        else:
                            print(f"Failed to verify OTP, status code: {token_response.status_code}")
                    else:
                        print(f"Failed to send OTP, status code: {otp_response.status_code}")
        else:
            print("[-] Failed to download captcha image.")
    else:
        print("[+]OTP sent successfully.")
        otp = input("[+]Enter the OTP: ")
        
        # Verify OTP to get authentication token
        verify_data = {
            "attestation": {"method": "skip", "platform": "skip"},
            "grant_type": "sms_v2",
            "client_id": "ios_sadjfhasd9871231hfso234",
            "client_secret": "23497shjlf982734-=1031nln",
            "cellphone": phone_number,
            "token": otp,
            "referrer": "pwa",
            "device_id": "93a4d99a-38c4-4eec-9382-158563122584"
        }
        token_response = r.post('https://app.snapp.taxi/api/api-passenger-oauth/v3/mutotp/auth', json=verify_data, headers=headers, proxies=proxies, verify=False)
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            access_token = token_data.get('access_token')
            print(f"[+]Authentication token: {access_token}")
            
            # Send request to /api/api-base/v2/passenger/balance
            balance_data = {
                "place": "sidemenu-topup"
            }
            balance_headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": headers['User-Agent'],
                'Cookie': 'cookiesession1=678B286C29D1A87602E7354E18ADE9F2; _ga_Y4QV007ERR=GS1.1.1734963808.8.1.1734964455.34.0.0; _ga=GA1.1.2013732041.1732458988; _ym_uid=1732458988792538382; _ym_d=1732458988; _ym_isad=1; _clck=2fvf85%7C2%7Cfry%7C0%7C1818; _clsk=16026nd%7C1734963797740%7C1%7C0%7Cp.clarity.ms%2Fcollect'
            }
            balance_response = r.post('https://app.snapp.taxi/api/api-base/v2/passenger/balance', json=balance_data, headers=balance_headers, proxies=proxies, verify=False)
            
            if balance_response.status_code == 200:
                print("[+]Balance request successful")
                balance_data = balance_response.json()
                balance = balance_data.get('data', {}).get('balance', 0)
                print(f"Your balance is: {balance}")
            else:
                print(f"Failed to send balance request, status code: {balance_response.status_code}")
        else:
            print(f"Failed to verify OTP, status code: {token_response.status_code}")
else:
    print(f"Failed to send OTP, status code: {otp_response.status_code}")