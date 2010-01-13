PyChap
======

Advanced challenge response authentication for Python
-----------------------------------------------------

PyChap is a server side Python implementation of a challenge response
authentication protocol used to authenticate users over a network.  It does not
require the storage of plain text passwords, and the stored password
equivalents are changed at the start of every session, or on every request over
the network, depending on the usage of this module.

Although there is a specification for [digest access
authentication][digest-rfc], PyChap is designed to implement a more robust
challenge response protocol described by [Paul Johnston] in what he calls the
[alternative system] (CHAP).

The functionality of PyChap is just some very simple logic code that may be included
in your project or simply used to better understand the alternative challenge
response protocol system.

CHAP works like this:
---------------------

### When a new user account is created:

1. The client sends a user name string to the server.
2. If the user does not exist, it is created. Otherwise the server responds with an indication that the user already exists.
3. If the user was created a 'nonce' and 'nextnonce' attributes are added. Both of these attributes are random, non-guessable, strings.
4. The server sends back the user name, the nonce, and the nextnonce.
5. The client hashes the nonce along with the user's password. We refer to this new string as the response.
6. The client hashes the nextnonce along with the user's password two times. We refer to this new string as the cnonce.
7. The client sends the user name string, the response, and the cnonce back to the server.
8. The server assigns the nonce user attribute to the value of the nextnonce user attribute.
9. The server assigns the nextnonce user attribute to a newly created random string.
10. The server assigns the cnonce from the client to the passkey attribute of the user. 
11. The server stores the user, completing the user creation process.

In the following pseudo code example the hash() function is a sha1 hash.

    CLIENT -> [username="foo_man_choo"] -> SERVER
    SERVER user = User() or abort()
    SERVER nonce = createNonce() and nextnonce = createNonce()
    SERVER -> [username="foo_man_choo", nonce="sdfp0893w4r", nextnonce="sd09u234"] -> CLIENT
    CLIENT response = hash(nonce + passkey)
    CLIENT cnonce = hash(hash(nextnonce + passkey))
    CLIENT -> [username="foo_man_choo", cnonce="lksdf09", response="asdf098w"] -> SERVER
    SERVER user.nonce = user.nextnonce, user.nextnonce = createNonce(), user.passkey = cnonce
    SERVER persists user data

### When authentication is requested for an existing user:

1. The client sends a username string.
2. The server responds with the last known nonce and nexnonce.
3. The client hashes the nonce along with the user's password. We refer to this new string as the response.
4. The client hashes the nextnonce along with the user's password two times. We refer to this new string as the cnonce.
5. The client sends the user name string, the response, and the cnonce back to the server.
6. The server then performs a hash on the response string. If the new hash matches the stored passkey for the user, the user is authenticated. If not, the user is denied.
7. If the user was authenticated, the server assigns the nonce user attribute to the value of the nextnonce user attribute.
8. If the user was authenticated, the server assigns the nextnonce user attribute to a newly created random string.
9. If the user was authenticated, the server assigns the cnonce from the client to the passkey attribute of the user. 
10. The server stores the user, completing the user authentication process.

In the following pseudo code example the hash() function is a sha1 hash.

    CLIENT -> [username="foo_man_choo"] -> SERVER
    SERVER nonce = createNonce() and nextnonce = createNonce()
    SERVER -> [username="foo_man_choo", nonce="sdfp0893w4r", nextnonce="sd09u234"] -> CLIENT
    CLIENT response = hash(nonce + passkey)
    CLIENT cnonce = hash(hash(nextnonce + passkey))
    CLIENT -> [username="foo_man_choo", cnonce="lksdf09", response="asdf098w"] -> SERVER
    SERVER if hash(response) != user.passkey abort()
    SERVER user.nonce = user.nextnonce, user.nextnonce = createNonce(), user.passkey = cnonce
    SERVER persists user data

### Check out the documentation in pychap.py to learn more about the PyChap implementation of this protocol.

Dependencies
------------
The hamac module and the hashlib module.

Usage
-----
PyChap has only been tested on Python 2.5 and Python 2.6

Simply grab a copy of pychap.py, add it to your project and import it into your
server side script where authentication takes place. See the docs for the
authenticate() function for more info.


### I'd like to know what you think.
  - [@kixxauth]
  - There will be a blog post with comments before long
  - Drop me a note on GitHub with the messaging system

Previous Work
-------------
  - [Peter Chng] did a PHP and Javascript [implementation][chng-chap]

License
-------
Licensed under The MIT License:

The MIT License

Copyright (c) 2009 Fireworks Technology Projects Inc.
[www.fireworksproject.com](http://www.fireworksproject.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

  [digest-rfc]:http://tools.ietf.org/html/rfc2617#section-3
  [Paul Johnston]:mailto:paj@pajhome.org.uk
  [alternative system]:http://pajhome.org.uk/crypt/md5/advancedauth.html#alternative
  [chng-chap]:http://unitstep.net/blog/2008/03/29/a-challenge-response-ajax-php-login-system/
  [Peter Chng]:http://unitstep.net/about

  [@kixxauth]:http://twitter.com/kixxauth
