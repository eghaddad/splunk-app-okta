import logging
import configure as conf
import credentials as cred


_LOGGER = logging.getLogger("ta_conf")


class AppConfManager(object):

    ENCRYPTED_MAGIC_TOKEN = "******"
    USER_PASS_MAGIC_SEP = "``"
    DUMMY = "dummy"

    def __init__(self, conf_file, splunkd_uri, session_key):
        if conf_file.endswith(".conf"):
            conf_file = conf_file[:-5]
        self._conf_file = conf_file
        self._conf_mgr = conf.ConfManager(splunkd_uri, session_key)
        self._cred_mgr = cred.CredentialManager(session_key, splunkd_uri)

    def create(self, appname, stanza, data, owner="nobody"):
        """
        @stanza: stanza name of the conf
        @data: a dict object
        @return: a dict if success otherwise None
        """

        return self.update(appname, stanza, data, owner)

    def update(self, appname, stanza, data, owner="nobody"):
        """
        @stanza: stanza name of the conf
        @data: dict like object
        @return: dict if sucess otherwise None
        """

        res = self.get(appname, stanza, owner)
        if res is None:
            # stanza doesn't exist, create it
            r, failed_stanzas = self._conf_mgr.create_conf(
                owner, appname, self._conf_file, (stanza,))
            if not r:
                return None

        r = self._encrypt_userpass(data, stanza, appname, owner)
        if not r:
            return None

        r = self._conf_mgr.update_conf_properties(
            owner, appname, self._conf_file, stanza, data)
        if not r:
            return None

        return self.get(appname, stanza, owner)

    def delete(self, appname, stanza, owner="nobody"):
        """
        @stanza: stanza name of the conf
        @data: dict like object
        @return: true if sucess otherwise false
        """

        res = self._conf_mgr.get_conf(owner, appname, self._conf_file, stanza)
        if res:
            self._delete_encrypted_userpass(res[0], appname, owner)
        else:
            return True

        res = self._conf_mgr.delete_conf_stanzas(
            owner, appname, self._conf_file, (stanza,))
        if res:
            return False
        return True

    def get(self, appname, stanza, owner="nobody", decrypt=True):
        """
        @stanza: stanza name of the conf
        @data: dict like object
        @return: dict object if sucess otherwise None
        """

        res = self._conf_mgr.get_conf(owner, appname, self._conf_file, stanza)
        if res:
            if decrypt:
                self._decrypt_userpass(res[0], appname, owner)
            return res[0]
        return None

    def all(self, appname="-", owner="-", decrypt=True):
        """
        @return: a list of dict objects if success
                 otherwise return empty list
        """

        results = []
        stanzas = self._conf_mgr.get_conf(owner, appname, self._conf_file)
        if not stanzas:
            return results

        for stanza in stanzas:
            if decrypt:
                self._decrypt_userpass(stanza, appname, owner)
            results.append(stanza)
        return results

    def _needs_decrypt(self, stanza):
        return False

    def _needs_encrypt(self, data):
        return False

    def _get_userpass(self, data):
        return ("", "")

    def _mask_userpass(self, data):
        pass

    def _set_clear_userpass(self, data, username, password):
        pass

    def _get_realm(self, data):
        raise NotImplementedError("Dervice class shall override this")

    def _delete_encrypted_userpass(self, data, appname, owner="nobody"):
        """
        @data: dict object contains clear username password
        @return: True if success otherwise false
        """

        if not self._needs_decrypt(data):
            return True

        realm = self._get_realm(data)
        return self._cred_mgr.delete(realm, self.DUMMY, appname, owner)

    def _encrypt_userpass(self, data, stanza, appname, owner="nobody"):
        """
        @stanza: stanza name of the conf
        @data: dict object contains clear username password
        @return: True if success otherwise false
        """

        if not self._needs_encrypt(data):
            return True

        realm = self._get_realm(data)
        real_userpass = self.USER_PASS_MAGIC_SEP.join(self._get_userpass(data))
        res = self._cred_mgr.update(
            realm, self.DUMMY, real_userpass, appname, owner)

        if res:
            self._mask_userpass(data)
        return res

    def _decrypt_userpass(self, data, appname, owner="nobody"):
        """
        @data: dict object contains encrypted username password
        @return: True if success otherwise false
        """

        if not self._needs_decrypt(data):
            return True

        realm = self._get_realm(data)
        res = self._cred_mgr.get_clear_password(
            realm, self.DUMMY, appname, owner)
        if not res:
            return res

        userpass = res.split(self.USER_PASS_MAGIC_SEP)
        self._set_clear_userpass(data, userpass[0], userpass[1])
        return True

    def reload(self):
        self._conf_mgr.reload_confs((self._conf_file,), "-")
