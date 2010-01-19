#! /usr/bin/env python

import unittest
import hashlib
import pychap

class Prototype(object):
  pass

class CreateNonce(unittest.TestCase):
  def testCreateNonce(self):
    """createNonce()"""
    nonce = pychap.createNonce('some_user_name')
    assert isinstance(nonce, basestring), \
        'createNonce() is expected to return a string.'
    self.assertEqual(len(nonce), 40)

  def testCreateMultipleNonce(self):
    """createNonce() multiple"""
    # test that no two consecutive hashes are the same
    def check(nonce, nextnonce):
      self.assertNotEqual(nonce, nextnonce)
      return nextnonce

    reduce(check, [pychap.createNonce('x') for n in range(100)])

class InvalidParams(unittest.TestCase):
  def testInvalidParams(self):
    """Invalid Params."""
    ex = False
    try:
      pychap.authenticate(None)
    except TypeError:
      ex = True
    assert ex, 'params (None) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None))
    except TypeError:
      ex = True
    assert ex, 'params (lambda, None) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None), 1)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, 1) raises exception.'

    user = Prototype()
    user.nonce = 4
    ex = False
    try:
      pychap.authenticate((lambda : None), user)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", 4) raises exception.'

    user = Prototype()
    user.username = 'x'
    user.nonce = 4
    ex = False
    try:
      pychap.authenticate((lambda : None), user)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", 4) raises exception.'

    user = Prototype()
    user.username = 'x'
    user.nonce = ''
    user.nextnonce = 99
    ex = False
    try:
      pychap.authenticate((lambda : None), user)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", "", "") raises exception.'

    user = Prototype()
    user.username = 'x'
    user.nonce = 'x'
    user.nextnonce = 'x'
    user.cnonce = 1
    ex = False
    try:
      pychap.authenticate((lambda : None), user)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", "", False) raises exception.'

    user = Prototype()
    user.username = 'x'
    user.nonce = 'x'
    user.nextnonce = 'x'
    user.cnonce = 'x'
    user.response = [1]
    ex = False
    try:
      pychap.authenticate((lambda : None), user)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, []) raises exception.'

class NewUser(unittest.TestCase):
  def callback(self, user):
    # nonce
    assert isinstance(user.nonce, basestring), \
        'nonce should be a string.'
    self.assertEqual(len(user.nonce), 40)

    #nextnonce
    assert isinstance(user.nextnonce, basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.nextnonce), 40)

    #passkey
    self.assertEqual(getattr(user, 'passkey', None), None)

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.USER_NA)

    self.user = user

  def testNewUser(self):
    """authenticate() a new user (no nonce or nextnonce)"""
    user = Prototype()
    user.someother = 1
    user.username = 'x'
    self.assertEqual(
        pychap.authenticate(self.callback, user),
        self.user)

class NoCreds(unittest.TestCase):
  def testNoCreds(self):
    """authenticate() a user with no creds"""
    user = Prototype()
    user.username = 'x'
    user.nonce = 'y'
    user.nextnonce = 'z'

    def callback(u):
      assert False, 'Callback called in MISSING_CREDS'

    user = pychap.authenticate(callback, user)

    # nonce
    self.assertEqual(user.nonce, 'y')

    #nextnonce
    self.assertEqual(user.nextnonce, 'z')

    #passkey
    self.assertEqual(getattr(user, 'passkey', None), None)

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.MISSING_CREDS)

class SettingPasskey(unittest.TestCase):
  def callback(self, user):
    #authmessage
    self.assertEqual(user.message, pychap.SETTING_PASSKEY)

    # nonce
    self.assertEqual(user.nonce, 'b')

    #nextnonce
    assert isinstance(user.nextnonce, basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.nextnonce), 40)

    #passkey
    self.assertEqual(user.passkey, 'c')

    #authenticated
    self.assertEqual(user.authenticated, True)

    self.user = user

  def testSetPasskey(self):
    """authenticate() a user with no passkey"""
    user = Prototype()
    user.username = 'x'
    user.nonce = 'a'
    user.nextnonce = 'b'
    user.cnonce = 'c'
    user.response = 'd'
    self.assertEqual(pychap.authenticate(self.callback, user),
        self.user)

class AuthWithoutModifiedPasskey(unittest.TestCase):
  def testWithoutModifiedPasskey(self):
    """authenticate() a user without a modified passkey"""
    nonce = 'a_nonce'
    nextnonce = 'a_nextnonce'
    response = hashlib.sha1(nonce).hexdigest()
    cnonce = hashlib.sha1(
      hashlib.sha1(nextnonce).hexdigest()).hexdigest()
    user = Prototype()
    user.username = 'x'
    user.nonce = nonce
    user.nextnonce = nextnonce
    user.cnonce = cnonce
    user.response = response
    user.passkey = 'y'

    def callback(u):
      assert False, 'Callback called in MISSING_CREDS'

    user = pychap.authenticate(callback, user)

    # nonce
    self.assertEqual(user.nonce, nonce)

    #nextnonce
    self.assertEqual(user.nextnonce, nextnonce)

    #passkey
    self.assertEqual(user.passkey, 'y') 

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.UNMODIFIED)

class NotAuthenticated(unittest.TestCase):
  def testInvalidPasskey(self):
    """invalid passkey"""
    user = Prototype()
    user.username = 'x'
    user.nonce = 'x'
    user.nextnonce = 'x'
    user.cnonce = 'x'
    user.response = 'x'
    user.passkey = []

    def callback(u):
      assert False, 'Callback called in MISSING_CREDS'

    ex = False
    try:
      user = pychap.authenticate(callback, user)
    except AssertionError, ae:
      ex = ae

    assert ex.message, \
        ('pychap.authenticate() '
         'should raise an exception for an invalid passkey.')

  def testPasskey(self):
    """user is not authenticated"""
    user = Prototype()
    user.username = 'x'
    user.nonce = 'x'
    user.nextnonce = 'x'
    user.cnonce = 'x'
    user.response = 'x'
    user.passkey = 'x'

    def callback(u):
      assert False, 'Callback called in MISSING_CREDS'

    user = pychap.authenticate(callback, user)

    # nonce
    self.assertEqual(user.nonce, 'x')

    #nextnonce
    self.assertEqual(user.nextnonce, 'x')

    #passkey
    self.assertEqual(user.passkey, 'x')

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.DENIED)

class Authenticated(unittest.TestCase):
  def callback(self, user):
    # nonce
    self.assertEqual(user.nonce, 'c')

    #nextnonce
    assert isinstance(user.nextnonce, basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.nextnonce), 40)

    #passkey
    self.assertEqual(user.passkey, 'd')

    #authenticated
    self.assertEqual(user.authenticated, True)

    #authmessage
    self.assertEqual(user.message, pychap.OK)

    self.user = user

  def testNewUser(self):
    """user authenticates"""
    user = Prototype()
    user.username = 'a'
    user.nonce = 'b'
    user.nextnonce = 'c'
    user.cnonce = 'd'
    user.response = 'e'
    user.passkey = '58e6b3a414a1e090dfc6029add0f3555ccba127f'
    self.assertEqual(
        pychap.authenticate(self.callback, user),
        self.user)

class Unicode(unittest.TestCase):
  def callback(self, user):
    # nonce
    self.assertEqual(user.nonce, 'c')

    #nextnonce
    assert isinstance(user.nextnonce, basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.nextnonce), 40)

    #passkey
    self.assertEqual(user.passkey, 'd')

    #authenticated
    self.assertEqual(user.authenticated, True)

    #authmessage
    self.assertEqual(user.message, pychap.OK)

    self.user = user

  def testNewUser(self):
    """user authenticates"""
    user = Prototype()
    user.username = u'a'
    user.nonce = u'b'
    user.nextnonce = u'c'
    user.cnonce = u'd'
    user.response = u'e'
    user.passkey = u'58e6b3a414a1e090dfc6029add0f3555ccba127f'
    self.assertEqual(
        pychap.authenticate(self.callback, user),
        self.user)

if __name__ == '__main__':
    unittest.main()
