import hashlib
import hmac
import datetime
import random

USER_NA = 'user does not exist'
MISSING_CREDS = 'proper cnonce or response was not supplied'
SETTING_PASSKEY = 'setting or resetting the user passkey'
UNMODIFIED = 'the cnonce or response were not modified'
DENIED = 'the supplied passkey response did not authenticate'
OK = 'authenticated ok'

def createNonce(username):
  return hmac.new(
      str(datetime.datetime.utcnow()) + username,
      str(random.randint(0, 9999)),
      hashlib.sha1).hexdigest()

def authenticate(user, putuser):
  if not isinstance(user, dict):
    return None

  assert callable(putuser), \
      'second argument to pychap.authenticate() should be a function'

  assert isinstance(user.get('username'), basestring), \
      'user["username"] passed to pychap.authenticate() should be a string.'

  # new user
  if user.get('nonce') is None or user.get('nextnonce') is None:
    user['nonce'] = createNonce(user['username'])
    user['nextnonce'] = createNonce(user['username'])
    user['authmessage'] = USER_NA
    user['authenticated'] = False
    putuser(user)
    return user 

  # no credentials supplied by the client
  if user.get('cnonce') is None or user.get('response') is None:
    user['authmessage'] = MISSING_CREDS 
    user['authenticated'] = False
    return user

  # no stored passkey: setting or re-setting the passkey
  if user.get('passkey') is None:
    user['passkey'] = user['cnonce']
    user['nonce'] = user['nextnonce']
    user['nextnonce'] = createNonce(user['username'])
    user['authenticated'] = True
    user['authmessage'] = SETTING_PASSKEY
    putuser(user)
    return user

  # Now that we know we have a passkey, nonce, and nextnonce for the user we
  # have to make sure that the client has at least modified nonce and nextnonce
  # into response and cnonce with user's passkey.
  assert isinstance(user.get('nonce'), basestring), \
      'user["nonce"] passed to pychap.authenticate() should be a string.'

  assert isinstance(user.get('nextnonce'), basestring), \
      'user["nextnonce"] passed to pychap.authenticate() should be a string.'

  if user['cnonce'] == hashlib.sha1(
      hashlib.sha1(user['nextnonce']).hexdigest()).hexdigest() \
          or user.get('response') == hashlib.sha1(user['nonce']).hexdigest():
    user['authenticated'] = False
    user['authmessage'] = UNMODIFIED
    return user

  # authenticate
  assert isinstance(user.get('passkey'), basestring), \
      'user["passkey"] passed to pychap.authenticate() should be a string.'
  if hashlib.sha1(user.get('response')).hexdigest() != user['passkey']:
    user['authenticated'] = False
    user['authmessage'] = DENIED
    return user

  # user is ok
  user['passkey'] = user['cnonce']
  user['nonce'] = user['nextnonce']
  user['nextnonce'] = createNonce(user['username'])
  user['authenticated'] = True
  user['authmessage'] = OK
  putuser(user)
  return user
