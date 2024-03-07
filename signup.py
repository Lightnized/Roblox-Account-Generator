import base64
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from urllib.parse import unquote
import time
import random
import string
import json
import threading
from datetime import datetime
from colorama import Fore

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0" # You can set your own user agent if you want.
PREFIX = False # False if you want no prefix, if you want a prefix make it something like "prefixcowlol_".
LENGTH_AFTER_PREFIX_RANGE = [2, 5] # The amount of characters after the prefix. So for the current value 2 - 5 characters after the prefix.
REALISTIC_USERNAMES = True # True or False based on whether you want realistic usernames.
CAPBYPASS_API_KEY = "Put the key here" # Your API key to CapBypass goes here.
THREAD_COUNT = 10 # The amount of accounts being generated at the same time.
VERIFY_ACCOUNTS = True # True or False based on whether you want to email verify the generated accounts.
FAVOURITE_GAME = False # True or False based on whether you want to favourite a game or not.
GAME_ID = 1094479103 # The game ID you want to bot.

lock = threading.Lock()

def print_thread_safe(text):
    with lock:
        print(text)

class Output:
    def __init__(this, level):
        this.level = level
        this.color_map = {
            "INFO": (Fore.LIGHTBLUE_EX, "*"),
            "INFO2": (Fore.LIGHTCYAN_EX, "^"),
            "CAPTCHA": (Fore.LIGHTMAGENTA_EX, "🤖"),
            "ERROR": (Fore.LIGHTRED_EX, "❌"),
            "SUCCESS": (Fore.LIGHTGREEN_EX, "✅"),
            "FAVOURITE": (Fore.YELLOW, "🌟"),
            "MAIL": (Fore.RESET, "📩"),
            "HUMANIZE": (Fore.YELLOW, "👦")
        }

    def log(this, *args, **kwargs):
        color, text = this.color_map.get(this.level, (Fore.LIGHTWHITE_EX, this.level))
        time_now = datetime.now().strftime("%H:%M:%S")

        base = f"{Fore.LIGHTBLACK_EX}[{time_now}]{Fore.RESET} ({color}{text.upper()}{Fore.RESET})"
        for arg in args:
            base += f"{Fore.LIGHTCYAN_EX} {arg}"
        if kwargs:
            base += f"{Fore.LIGHTCYAN_EX} {arg}"
        return base

def getRandomProxy():
    with open("proxies.txt", "r", encoding="utf-8") as file:
        lines = file.readlines()
        proxies = [line.split("\n")[0] for line in lines]
        proxy = random.choice(proxies)
    return proxy

def string_to_bytes(raw_string):
    return bytes(raw_string, 'utf-8')

def export_public_key_as_spki(public_key):
    spki_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki_bytes).decode('utf-8')

def generate_signing_key_pair_unextractable():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def getAuthIntent(proxy=None):
    try:
        if proxy == None:
            key_pair = generate_signing_key_pair_unextractable()
            private_key, public_key = key_pair
            client_public_key = export_public_key_as_spki(public_key)
            client_epoch_timestamp = str(int(time.time()))
            response = requests.get("https://apis.roblox.com/hba-service/v1/getServerNonce", headers={"content-type": "application/json; charset=utf-8"})
            server_nonce = response.text.strip('"')
            payload = f"{client_public_key}|{client_epoch_timestamp}|{server_nonce}"
            sai_signature = sign(private_key, string_to_bytes(payload))
            result = {
                "clientEpochTimestamp": client_epoch_timestamp,
                "clientPublicKey": client_public_key,
                "saiSignature": sai_signature,
                "serverNonce": server_nonce
            }
            return result
        else:
            proxy_url = f"http://{proxy}"
            key_pair = generate_signing_key_pair_unextractable()
            private_key, public_key = key_pair
            client_public_key = export_public_key_as_spki(public_key)
            client_epoch_timestamp = str(int(time.time()))
            response = requests.get("https://apis.roblox.com/hba-service/v1/getServerNonce", headers={"content-type": "application/json; charset=utf-8"}, proxies={"http": proxy_url})
            server_nonce = response.text.strip('"')
            payload = f"{client_public_key}|{client_epoch_timestamp}|{server_nonce}"
            sai_signature = sign(private_key, string_to_bytes(payload))
            result = {
                "clientEpochTimestamp": client_epoch_timestamp,
                "clientPublicKey": client_public_key,
                "saiSignature": sai_signature,
                "serverNonce": server_nonce
            }
            return result
    except:
        return None
    
def getBirthDay():
    days = [str(i).zfill(2) for i in range(1, 29)]
    months = [str(i).zfill(2) for i in range(1, 13)]
    years = [str(x) for x in range(1997, 2007)]
    return f"{random.choice(years)}-{random.choice(months)}-{random.choice(days)}T23:00:00.000Z"

def returnGender():
    return str(random.randint(1, 2))

def getUsername():
    if PREFIX == False:
        username = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(8, 18)))
        return username
    else:
        username = f"{PREFIX}{''.join(random.choice(string.ascii_letters) for _ in range(random.randint(LENGTH_AFTER_PREFIX_RANGE[0], LENGTH_AFTER_PREFIX_RANGE[1])))}"
        return username
    
def getRealisticUsername():
    if PREFIX == False:
        with open('words.txt', 'r') as file:
            words = file.readlines()
        words = [word.strip() for word in words if word.strip()]

        while True:
            word1 = random.choice(words)
            word1 = word1[0].upper() + word1[1:]
            word2 = random.choice(words)
            word2 = word2[0].upper() + word2[1:]
            numbers = [random.randint(10, 99), random.randint(100, 999), random.randint(1000, 9999)]
            numbers = random.choice(numbers)
            combined_length = len(word1) + len(word2) + len(str(numbers))
            combined_length2 = len(word1) + len(str(numbers))
            if combined_length <= 20 and combined_length >= 6 and combined_length2 <= 20 and combined_length2 >= 6:
                return random.choice([word1 + word2 + str(numbers), word1 + str(numbers)])
    else:
        username = f"{PREFIX}{''.join(random.choice(string.ascii_letters) for _ in range(random.randint(LENGTH_AFTER_PREFIX_RANGE[0], LENGTH_AFTER_PREFIX_RANGE[1])))}"
        return username

def getPassword():
    password_length = random.randint(8, 17)
    characters = string.ascii_letters
    password = ''.join(random.choice(characters) for _ in range(password_length))
    return password
    
def getValues(session: requests.Session, birthday: str):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://www.roblox.com",
        "Referer": "https://www.roblox.com/",
        'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": USER_AGENT
    }

    while True:
        username = getRealisticUsername() if REALISTIC_USERNAMES else getUsername()
        response = session.post("https://auth.roblox.com/v1/usernames/validate", headers=headers, json={"username": username, "birthday": birthday, "context": "Signup"})
        if response.headers.get("X-Csrf-Token"):
            headers["X-Csrf-Token"] = response.headers["X-Csrf-Token"]
            continue

        if "Username is valid" in response.text:
            try:
                if len(response.cookies) > 1:
                    return [username, '; '.join([f'{key}={value}' for key, value in response.cookies.get_dict().items()]), headers["X-Csrf-Token"]]
                else:
                    return [username, response.headers["Set-Cookie"].split(";")[0], headers["X-Csrf-Token"]]
            except:
                return [username, None, headers["X-Csrf-Token"]]
            
class TempMail:
    def __init__(self, session: requests.Session):
        self.session = session
        self.email = None
        self.token = None
    
    def create_inbox(self):
        responseJson = self.session.get("https://api.tempmail.lol/v2/inbox/create").json()
        self.token = responseJson["token"]
        self.email = responseJson["address"]

    def get_inbox(self):
        emails = self.session.get(f"https://api.tempmail.lol/v2/inbox?token={self.token}").json()["emails"]
        return emails

def main(threadNum):
    while True:
        try:
            proxy = getRandomProxy()
            proxies = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }
            session = requests.Session()
            session.proxies.update(proxies)

            birthday = getBirthDay()
            values = getValues(session, birthday)
            password = getPassword()
            gender = returnGender()

            if values[1] != None:
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                    "Cookie": str(values[1]),
                    "Content-Type": "application/json;charset=UTF-8",
                    "Origin": "https://www.roblox.com",
                    "Referer": "https://www.roblox.com/",
                    'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-site",
                    "User-Agent": USER_AGENT,
                    "X-Csrf-Token": values[2]
                }
                timgResponse = session.get("https://www.roblox.com/timg/rbx", headers=headers)

                headers["Cookie"] = headers["Cookie"] + '; ' + '; '.join([f'{key}={value}' for key, value in timgResponse.cookies.get_dict().items()])
            else:
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Origin": "https://www.roblox.com",
                    "Referer": "https://www.roblox.com/",
                    'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-site",
                    "User-Agent": USER_AGENT,
                    "X-Csrf-Token": values[2]
                }
                timgResponse = session.get("https://www.roblox.com/timg/rbx", headers=headers)

                headers["Cookie"] = '; '.join([f'{key}={value}' for key, value in timgResponse.cookies.get_dict().items()])

            authIntent = getAuthIntent(proxy)

            payload = {
                "agreementIds": '["3f341564-2a8b-4d10-8b1b-fd6e20d0a88a", "c52851e3-faeb-4853-a597-12e374f8aa98"]',
                "birthday": birthday,
                "gender": gender,
                "isTosAgreementBoxChecked": "True",
                "password": password,
                "username": values[0],
                "securityAuthIntent": authIntent
            }

            signupResponse = session.post("https://auth.roblox.com/v2/signup", headers=headers, json=payload)

            challengeData = json.loads(base64.b64decode(signupResponse.headers.get("Rblx-Challenge-Metadata")).decode())
            dataBlob = challengeData["dataExchangeBlob"]
            unifiedCaptchaId = challengeData["unifiedCaptchaId"]
            challengeId = challengeData["sharedParameters"]["genericChallengeId"]

            print_thread_safe(Output("CAPTCHA").log(f"Solving captcha. | Thread: {str(threadNum)}"))

            taskId = requests.post("https://capbypass.com/api/createTask", json={
                "clientKey": CAPBYPASS_API_KEY,
                "task": {
                    "type": "FunCaptchaTask",
                    "websiteURL": "https://www.roblox.com/",
                    "websitePublicKey": "A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
                    "websiteSubdomain": "roblox-api",
                    "proxy": proxy if "@" not in proxy else f'{proxy.split("@")[1].split(":")[0]}:{proxy.split("@")[1].split(":")[1]}:{proxy.split(":")[0]}:{proxy.split(":")[1].split("@")[0]}',
                    "data": json.dumps({"blob": dataBlob})
                }
            }).json()["taskId"]

            while True:
                reqToSolve = requests.post("https://capbypass.com/api/getTaskResult", json={
                    "clientKey": CAPBYPASS_API_KEY,
                    "taskId": taskId
                })
                if reqToSolve.json().get("solution") != None:
                    break
                if reqToSolve.json()["errorId"] == 1:
                    raise ValueError("Captcha failed to solve.")
                time.sleep(1)

            reqToSolveJson = reqToSolve.json()

            print_thread_safe(Output("CAPTCHA").log(f"Captcha Solved | Token: {reqToSolveJson['solution']} | Thread: {str(threadNum)}"))

            metadata = json.dumps({
                "unifiedCaptchaId": unifiedCaptchaId,
                "captchaToken": reqToSolveJson["solution"],
                "actionType": "Signup"
            })

            payloadd = json.dumps({
                "challengeId": signupResponse.headers.get("Rblx-Challenge-Id"),
                "challengeMetadata": metadata,
                "challengeType": "captcha"
            }).replace(" ", "")

            continueApiUrl = "https://apis.roblox.com/challenge/v1/continue"

            continueResponse = session.post(url=continueApiUrl, data=payloadd, headers=headers)

            if continueResponse.status_code != 200:
                raise ValueError("Rejected token by continue API.")

            stringg = '{"unifiedCaptchaId":"' + unifiedCaptchaId + '","captchaToken":"' + reqToSolveJson["solution"] + '","actionType":"Signup"}'

            stuffToEncode = base64.b64encode(stringg.encode()).decode()

            headers['Rblx-Challenge-Metadata'] = stuffToEncode
            headers['Rblx-Challenge-Id'] = challengeId
            headers['Rblx-Challenge-Type'] = 'captcha'

            response = session.post("https://auth.roblox.com/v2/signup", headers=headers, json=payload)

            try:
                cookie = str(response.headers.get('Set-Cookie')).split('.ROBLOSECURITY=')[1].split(';')[0]
                userId = response.json()["userId"]
            except:
                raise ValueError("Failed to retrieve cookie from signup request.")

            print_thread_safe(Output('SUCCESS').log(f'Generated {values[0]} successfully. | Thread: {str(threadNum)}'))

            with threading.Lock():
                with open('accounts.txt', 'a', encoding='utf-8') as file:
                    file.write(values[0] + ':' + password + ':' + cookie + ':' + str(userId) + '\n')
                    file.close()

            headers = {
                'Accept': '*/*',
                'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
                'Cache-Control': 'no-cache',
                'Cookie': f'.ROBLOSECURITY={cookie}; {headers["Cookie"]}',
                'Origin': 'https://www.roblox.com',
                'Pragma': 'no-cache',
                'Referer': 'https://www.roblox.com',
                'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'User-Agent': USER_AGENT
            }

            response = session.post("https://accountsettings.roblox.com/v1/email", headers=headers)
            csrf = response.headers.get("x-csrf-token")
            headers["X-Csrf-Token"] = csrf

            if VERIFY_ACCOUNTS:
                print_thread_safe(Output('MAIL').log(f'Attempting to email verify account {str(userId)}. | Thread: {str(threadNum)}'))
                tempMail = TempMail(session)
                tempMail.create_inbox()
                email = tempMail.email
                payload = {"emailAddress": email, "password": ""}
                robloxEmailResponse = session.post(f"https://accountsettings.roblox.com/v1/email?emailAddress={email}&password=", json=payload, headers=headers)
                if robloxEmailResponse.status_code != 200:
                    raise ValueError(f"Failed to email verify account {str(userId)}.")
                robloxVerifyEmail = None
                attempts = 0
                while True:
                    attempts += 1
                    if attempts == 30:
                        raise ValueError(f"Failed to email verify account {str(userId)}.")
                    inbox = tempMail.get_inbox()
                    if len(inbox) == 0:
                        time.sleep(1)
                    else:
                        robloxVerifyEmail = inbox[0]['body'].split("Verify Email ( ")[1].split(" )")[0]
                        break

                session.proxies = {}
                ticketToSend = unquote(robloxVerifyEmail.split('ticket=')[1])
                verifyAccountResponse = session.post("https://accountinformation.roblox.com/v1/email/verify", json={"ticket": ticketToSend}, headers=headers)
                if verifyAccountResponse.status_code == 200:
                    print_thread_safe(Output('MAIL').log(f'Successfully email verified account {str(userId)}. | Thread: {str(threadNum)}'))
                else:
                    raise ValueError(f"Failed to email verify account {str(userId)}.")

            if FAVOURITE_GAME:
                print_thread_safe(Output('FAVOURITE').log(f'Attempting to favourite game {str(GAME_ID)}. | Thread: {str(threadNum)}'))
                response = session.post("https://www.roblox.com/favorite/toggle", data={"assetId": GAME_ID}, headers=headers)
                if response.status_code == 200:
                    print_thread_safe(Output('FAVOURITE').log(f'Favourited game {str(GAME_ID)} successfully. | Thread: {str(threadNum)}'))
                else:
                    raise ValueError(f'Failed to favourite game {str(GAME_ID)}.')

        except Exception as e:
            print_thread_safe(Output('ERROR').log(str(f'{e} | Thread: {str(threadNum)}')))

if __name__ == "__main__":
    for x in range(THREAD_COUNT):
        thread = threading.Thread(target=main, args=(x + 1,))
        thread.start()