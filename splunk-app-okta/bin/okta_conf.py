import os
from ta_util import app_conf as ac
from ta_util import utils

_LOGGER = utils.setup_logging("ta_okta_conf")


class OktaConfManager(ac.AppConfManager):
    okta_endpoint = "okta_endpoint"

    def __init__(self, splunkd_uri, session_key):
        super(OktaConfManager, self).__init__("okta", splunkd_uri, session_key)

    def get_okta_endpoint(self):
        appname = utils.get_appname_from_path(os.path.abspath(__file__))
        account = self.get(appname, self.okta_endpoint, decrypt=False)
        if not account or not account["endpoint"] or not account["token"]:
            return None

        keys = ("token", "endpoint", "proxy_url")
        if account["token"] != self.ENCRYPTED_MAGIC_TOKEN:
            update_dict = {key: account.get(key, "") for key in keys}
            res = self.update(appname, self.okta_endpoint, update_dict)
            if not res:
                raise Exception("Failed to encrypt okta credentials")
        account = self.get(appname, self.okta_endpoint)
        return {key: account[key] if account[key] else "" for key in keys}

    def _needs_encrypt(self, data):
        if not data:
            return False

        return data.get("token") != self.ENCRYPTED_MAGIC_TOKEN

    def _needs_decrypt(self, data):
        if not data:
            return False

        return data.get("token") == self.ENCRYPTED_MAGIC_TOKEN

    def _get_userpass(self, data):
        return (data.get("token"), data.get("token"))

    def _get_realm(self, data):
        return data["endpoint"]

    def _mask_userpass(self, data):
        data["token"] = self.ENCRYPTED_MAGIC_TOKEN

    def _set_clear_userpass(self, data, username, password):
        data["token"] = password
        return data


if __name__ == "__main__":
    import sys
    import os.path as op
    bindir = op.dirname(op.dirname(op.abspath(__file__)))
    sys.path.append(bindir)

    import ta_util
    from ta_util import utils
    from ta_util import credentials as cred

    data = {
        "endpoint": "172.16.107.244",
        "token": "abc",
        "proxy_url": "admin@proxy.comd:800",
    }

    appname = utils.get_appname_from_path(os.path.abspath(__file__))
    stanza_name = OktaConfManager.okta_endpoint

    session_key = cred.CredentialManager.get_session_key("admin", "admin")
    mgr = OktaConfManager("https://localhost:8089", session_key)
    res = mgr.create(appname, stanza_name, data)
    assert res

    res = mgr.get(appname, stanza_name)
    assert res["token"] == "abc"

    data["token"] = "Password1"
    res = mgr.update(appname, stanza_name, data)
    assert res
    res = mgr.get(appname, stanza_name)
    assert res["token"] == "Password1"
    res = mgr.delete(appname, stanza_name)
    # stanza in conf under default dir can't be deleted
    # assert res
