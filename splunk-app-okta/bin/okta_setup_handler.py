import splunk.clilib.cli_common as scc
import splunk.admin as admin
import splunk.entity as en
import os
import re
import platform


import okta_conf as oc
from ta_util import utils
from ta_util import configure as conf

_LOGGER = utils.setup_logging("ta_okta_setup")

# import your required python modules

'''
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values
      corresponds to handleractions = edit in restmap.conf

'''

class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''

  okta_endpoint = "okta_endpoint"
  okta_args = ("endpoint", "token")
  encrypted = "******"
  userpass_sep = "``"
  dummy = "dummy"

  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['endpoint', 'token']:
        self.supportedArgs.addOptArg(arg)

  '''
  Read the initial values of the parameters from the custom file
      okta.conf, and write them to the setup screen.

  If the app has never been set up,
      uses .../<appname>/default/okta.conf.

  If app has been set up, looks at
      .../local/okta.conf first, then looks at
  .../default/okta.conf only if there is no value for a field in
      .../local/okta.conf

  For text fields, if the conf file says None, set to the empty string.
  '''

  def handleList(self, confInfo):
    _LOGGER.info("start list")

    conf.reload_confs(("okta",), self.getSessionKey(), scc.getMgmtUri())
    conf_mgr = oc.OktaConfManager(scc.getMgmtUri(), self.getSessionKey())
    confDict = conf_mgr.get(self.appName, self.okta_endpoint)

    if confDict:
        for key, val in confDict.iteritems():
            if key in self.okta_args:
                if val is None:
                    val = ""
                confInfo[self.okta_endpoint].append(key, val)
    _LOGGER.info("end list")

  '''
  After user clicks Save on setup screen, take updated parameters,
  normalize them, and save them somewhere
  '''

  def handleEdit(self, confInfo):
      _LOGGER.info("start edit")

      args = self.callerArgs.data
      for arg in self.okta_args:
          if args.get(arg, None) and args[arg][0] is None:
              args[arg][0] = ""

      self._handleUpdateOktaAccount(confInfo, args)

      _LOGGER.info("end edit")

  def _handleUpdateOktaAccount(self, confInfo, args):
      settings = ("endpoint", "token")

      for k in settings:
          if not args.get(k, None) or not args[k][0]:
              err_msg = 'Okta "{}" is mandantory'.format(k)
              _LOGGER.error(err_msg)
              raise admin.ArgValidationException(err_msg)
      self._handleUpdateAccount(confInfo, args, self.okta_endpoint, settings)

  def _handleUpdateAccount(self, confInfo, args, stanza, settings):
      account = {}
      for k in settings:
          if args.get(k, None):
              account[k] = args[k][0]
              confInfo[stanza].append(k, args[k])

      conf_mgr = oc.OktaConfManager(scc.getMgmtUri(), self.getSessionKey())
      res = conf_mgr.update(self.appName, stanza, account)
      if not res:
          _LOGGER.error("Failed to commit settings")
          raise admin.ArgValidationException("Failed to commit settings")


# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
