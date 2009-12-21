import hashlib

USER_NA = 'user does not exist'
MISSING_CREDS = 'proper cnonce or response was not supplied'
SETTING_PASSKEY = 'setting or resetting the user passkey'
UNMODIFIED = 'the cnonce or response were not modified'
DENIED = 'the supplied passkey response did not authenticate'
OK = 'authenticated ok'

def createNonce():
  return False

def authenticate(user, putuser):
  if not isinstance(user, dict):
    return None

  # new user
  if user.get('nonce') is None or user.get('nextnonce') is None:
    user['nonce'] = createNonce()
    user['nextnonce'] = createNonce()
    putuser(user)
    user['authmessage'] = USER_NA
    user['authenticated'] = False
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
    user['nextnonce'] = createNonce()
    putuser(user)
    user['authenticated'] = True
    user['authmessage'] = SETTING_PASSKEY
    return user

  # Now that we know we have a passkey, nonce, and nextnonce for the user we
  # have to make sure that the client has at least modified nonce and nextnonce
  # into response and cnonce with user's passkey.
  if user['cnonce'] == hashlib.md5(
      hashlib.md5(user['nextnonce']).hexdigest()).hexdigest() \
          or user['response'] == hashlib.md5(user['nonce']).hexdigest():
    user['authenticated'] = False
    user['authmessage'] = UNMODIFIED
    return user

  # authenticate
  if hashlib.md5(response).hexdigest() != user['passkey']:
    user['authenticated'] = False
    user['authmessage'] = DENIED
    return user

  # user is ok
  user['passkey'] = user['cnonce']
  user['nonce'] = user['nextnonce']
  user['nextnonce'] = createNonce()
  putuser(user)
  user['authenticated'] = True
  user['authmessage'] = OK
  return user
