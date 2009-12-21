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

class AuthenticateNoUser(unittest.TestCase):
  def testNoUser(self):
    """call authenticate() with no user."""
    self.assertEqual(pychap.authenticate(None, None), None)

class AuthenticateInvalidUser(unittest.TestCase):
  def testList(self):
    """call authenticate() with a list as the user."""
    self.assertEqual(pychap.authenticate([], None), None)

  def testString(self):
    """call authenticate() with a string as the user."""
    self.assertEqual(pychap.authenticate('username', None), None)

class PassInvalidCallback(unittest.TestCase):
  def testNone(self):
    """call authenticate() with None as the callback."""
    ex = False
    try:
      pychap.authenticate(dict(), None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        'pychap.authenticate(dict(), None) should raise exception.'

  def testString(self):
    """call authenticate() with a string as the callback."""
    ex = False
    try:
      pychap.authenticate(dict(), 'user')
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        'pychap.authenticate(dict(), "user") should raise exception.'

class PassInvalidUsername(unittest.TestCase):
  def testNone(self):
    """call authenticate() with None as the callback."""
    ex = False
    try:
      pychap.authenticate(dict(), lambda : None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        'pychap.authenticate(dict(), lambda : None) should raise exception.'

  def testNumber(self):
    """call authenticate() with a string as the callback."""
    ex = False
    try:
      pychap.authenticate({'username':1}, lambda : None)
    except AssertionError, ae:
      ex = ae

    assert isinstance(ex, AssertionError), \
        ('pychap.authenticate({"username":1}, lambda : None) '
         'should raise exception.')

class NewUser(unittest.TestCase):
  def callback(self, user):
    # nonce
    assert isinstance(user.get('nonce'), basestring), \
        'nonce should be a string.'
    self.assertEqual(len(user.get('nonce')), 40)

    #nextnonce
    assert isinstance(user.get('nextnonce'), basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.get('nextnonce')), 40)

    #passkey
    self.assertEqual(user.get('passkey'), None)

    #authenticated
    self.assertEqual(user.get('authenticated'), False)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.USER_NA)

    self.user = user

  def testNewUser(self):
    """authenticate() a new user (no nonce or nextnonce)"""
    self.assertEqual(
        pychap.authenticate({'username':'foo'}, self.callback),
        self.user)

class NoCreds(unittest.TestCase):
  def testNoCreds(self):
    """authenticate() a user with no creds"""
    user = {'username':'x', 'nonce':0, 'nextnonce':1}
    user = pychap.authenticate(user, lambda : None)

    # nonce
    self.assertEqual(user.get('nonce'), 0)

    #nextnonce
    self.assertEqual(user.get('nextnonce'), 1)

    #passkey
    self.assertEqual(user.get('passkey'), None)

    #authenticated
    self.assertEqual(user.get('authenticated'), False)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.MISSING_CREDS)

class SettingPasskey(unittest.TestCase):
  def callback(self, user):
    # nonce
    self.assertEqual(user.get('nonce'), 1)

    #nextnonce
    assert isinstance(user.get('nextnonce'), basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.get('nextnonce')), 40)

    #passkey
    self.assertEqual(user.get('passkey'), 2)

    #authenticated
    self.assertEqual(user.get('authenticated'), True)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.SETTING_PASSKEY)

    self.user = user

  def testSetPasskey(self):
    """authenticate() a user with no passkey"""
    user = {
        'username':'x',
        'nonce':0,
        'nextnonce':1,
        'cnonce':2,
        'response':3
        }
    self.assertEqual(
        pychap.authenticate(user, self.callback),
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
    user = pychap.authenticate(user, lambda : None)

    # nonce
    self.assertEqual(user.get('nonce'), nonce)

    #nextnonce
    self.assertEqual(user.get('nextnonce'), nextnonce)

    #passkey
    self.assertEqual(user.get('passkey'), 1) 

    #authenticated
    self.assertEqual(user.get('authenticated'), False)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.UNMODIFIED)

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
    user = pychap.authenticate(user, lambda : None)

    # nonce
    self.assertEqual(user.get('nonce'), 'x')

    #nextnonce
    self.assertEqual(user.get('nextnonce'), 'x')

    #passkey
    self.assertEqual(user.get('passkey'), 'x')

    #authenticated
    self.assertEqual(user.get('authenticated'), False)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.DENIED)

class Authenticated(unittest.TestCase):
  def callback(self, user):
    # nonce
    self.assertEqual(user.get('nonce'), 'c')

    #nextnonce
    assert isinstance(user.get('nextnonce'), basestring), \
        'nextnonce should be a string.'
    self.assertEqual(len(user.get('nextnonce')), 40)

    #passkey
    self.assertEqual(user.get('passkey'), 'd')

    #authenticated
    self.assertEqual(user.get('authenticated'), True)

    #authmessage
    self.assertEqual(user.get('authmessage'), pychap.OK)

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
        pychap.authenticate(user, self.callback),
        self.user)

if __name__ == '__main__':
    unittest.main()
