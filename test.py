#! /usr/bin/env python

import unittest
import hashlib
import pychap

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
    except AssertionError:
      ex = True
    assert ex, 'params (None) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None))
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, None) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None), 1)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, 1) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None),
                          username='',
                          nonce=4)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", 4) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None),
                          username='',
                          nonce='',
                          nextnonce=99)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", "", "") raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None),
                          username='',
                          nonce='',
                          cnonce=False)
    except AssertionError:
      ex = True
    assert ex, 'params (lambda, "", "", False) raises exception.'

    ex = False
    try:
      pychap.authenticate((lambda : None), response=[])
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
    self.assertEqual(user.passkey, None)

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.USER_NA)

    self.user = user

  def testNewUser(self):
    """authenticate() a new user (no nonce or nextnonce)"""
    self.assertEqual(
        pychap.authenticate(self.callback, **{'username':'foo'}),
        self.user)

class NoCreds(unittest.TestCase):
  def testNoCreds(self):
    """authenticate() a user with no creds"""
    user = {'username':'x', 'nonce': 'y', 'nextnonce': 'z'}
    user = pychap.authenticate(lambda : None, **user)

    # nonce
    self.assertEqual(user.nonce, 'y')

    #nextnonce
    self.assertEqual(user.nextnonce, 'z')

    #passkey
    self.assertEqual(user.passkey, None)

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
    user = {
        'username': 'x',
        'nonce': 'a',
        'nextnonce': 'b',
        'cnonce': 'c',
        'response': 'd'
        }
    self.assertEqual(pychap.authenticate(self.callback, **user),
        self.user)

class AuthWithoutModifiedPasskey(unittest.TestCase):
  def testInvalidNonce(self):
    """invalid nonce"""
    user = {
        'username':'x',
        'nonce': 1,
        'nextnonce': 'x',
        'cnonce': 3,
        'response': 4,
        'passkey': 1
        }
    ex = False
    try:
      user = pychap.authenticate(user, lambda : None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        ('pychap.authenticate() '
         'should raise an exception for an invalid nonce.')

  def testInvalidNextnonce(self):
    """invalid nextnonce"""
    user = {
        'username':'x',
        'nonce': 'x',
        'nextnonce': 1,
        'cnonce': 3,
        'response': 4,
        'passkey': 1
        }
    ex = False
    try:
      user = pychap.authenticate(user, lambda : None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        ('pychap.authenticate() '
         'should raise an exception for an invalid nextnonce.')

  def testWithoutModifiedPasskey(self):
    """authenticate() a user without a modified passkey"""
    nonce = 'a_nonce'
    nextnonce = 'a_nextnonce'
    response = hashlib.sha1(nonce).hexdigest()
    cnonce = hashlib.sha1(
      hashlib.sha1(nextnonce).hexdigest()).hexdigest()
    user = {
        'username':'x',
        'nonce': nonce,
        'nextnonce': nextnonce,
        'cnonce': cnonce,
        'response': response,
        'passkey': 1
        }
    user = pychap.authenticate(lambda : None, **user)

    # nonce
    self.assertEqual(user.nonce, nonce)

    #nextnonce
    self.assertEqual(user.nextnonce, nextnonce)

    #passkey
    self.assertEqual(user.passkey, 1) 

    #authenticated
    self.assertEqual(user.authenticated, False)

    #authmessage
    self.assertEqual(user.message, pychap.UNMODIFIED)

class NotAuthenticated(unittest.TestCase):
  def testInvalidPasskey(self):
    """invalid passkey"""
    user = {
        'username':'x',
        'nonce': 'x',
        'nextnonce': 'x',
        'cnonce': 3,
        'response': 4,
        'passkey': []
        }
    ex = False
    try:
      user = pychap.authenticate(user, lambda : None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        ('pychap.authenticate() '
         'should raise an exception for an invalid passkey.')

  def testPasskey(self):
    """user is not authenticated"""
    user = {
        'username':'x',
        'nonce': 'x',
        'nextnonce': 'x',
        'cnonce': 'x',
        'response': 'x',
        'passkey': 'x'
        }
    user = pychap.authenticate(lambda : None, **user)

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
    user = {
        'username':'a',
        'nonce': 'b',
        'nextnonce': 'c',
        'cnonce': 'd',
        'response': 'e',
        'passkey': '58e6b3a414a1e090dfc6029add0f3555ccba127f'
        }
    self.assertEqual(
        pychap.authenticate(self.callback, **user),
        self.user)

if __name__ == '__main__':
    unittest.main()
