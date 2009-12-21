#! /usr/bin/env python

import unittest
import pychap

class CreateNonce(unittest.TestCase):
  def setUp(self):
    pass

  def tearDown(self):
    pass

  def testCreateNonce(self):
    """createNonce()"""
    nonce = pychap.createNonce()
    assert isinstance(nonce, basestring), \
        'createNonce() is expected to return a string.'

unittest.TestLoader().loadTestsFromTestCase(CreateNonce)

if __name__ == '__main__':
    unittest.main()
