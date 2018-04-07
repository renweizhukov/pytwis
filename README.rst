pytwis
======

This package contains two modules ``pytwis`` and ``pytwis_clt`` where

-  ``pytwis`` is a Twitter-toy-clone backend using Redis;
-  ``pytwis_clt`` is a command-line tool which uses ``pytwis`` to
   interact with the Redis database of the Twitter-toy clone.

To install this package,

.. code:: bash

    $ pip install pytwis

Note that

-  **This package requires Python 3.6 and later** since it depends on
   Python 3.6 built-in module
   `secrets <https://docs.python.org/3/library/secrets.html>`__.
-  There is a breaking change introduced in v0.4.0: the salted password
   hashes are stored in the Redis database instead of the plain-text
   passwords, so the Redis database created by the version before v0.4.0
   won’t work with the version v0.4.0 and after unless a manual database
   migration is done.

.. _pytwis-1:

1. ``pytwis``
-------------

1.1 Introduction
~~~~~~~~~~~~~~~~

This module implements the backend for a simplified Twitter clone based
on Redis. We follow the Redis tutorial
(https://redis.io/topics/twitter-clone) to design the data layout of the
Redis database.

It supports the following features:

-  Register new users
-  Log in/out
-  Change user password
-  Get user profile
-  Post tweets
-  Follower/Following
-  General timeline for anonymous user
-  User timeline
-  Get tweets posted by one user

TODOs:

-  Search users
-  Delete a user
-  Recover user password
-  #hashtags
-  @mentions
-  Retweets
-  Replies
-  Conversations
-  Edit/Delete tweets
-  And more

1.2 Sample usage
~~~~~~~~~~~~~~~~

Below is a sample usage of this module. You can find a more detailed
example in the module ``pytwis_clt``.

.. code:: python

    import pytwis

    # Connect to the Redis server by creating a Pytwis instance. 
    twis = pytwis.Pytwis()

    # You may specify the hostname, the port, the database index, and the password of the Redis server as keyword arguments.
    twis = pytwis.Pytwis(hostname='127.0.0.1', port=6379, db=0, password='password')

    # For all the following operations, if succeeded is False, check result['error'] for the error string.

    # Register a new user.
    succeeded, result = twis.register('username', 'password')

    # Log into the user. If succeeded is True, result['auth'] will contain the authentication secret.
    succeeded, result = twis.login('username', 'password')
    if succeeded:
        auth_secret = result['auth']

    # Post a tweet. 
    succeeded, result = twis.post_tweet(auth_secret, 'A tweet')

    # Get the general timeline. Note that we are passing an empty authentication secret and '-1' as the second 
    # input parameter to get all the tweets in the general timeline. 
    # If succeeded is True, result['tweets'] will contain a list of tweets.
    succeeded, result = twis.get_timeline('', -1)

    # Get the user timeline. Note that the second input parameter 100 specifies the maximum number of tweets 
    # that will be included in the general timeline.
    succeeded, result = twis.get_timeline(auth_secret, 100)

    # Get the tweets posted by a user. Note that this user may be different from the currently logged-in user.
    # If succeeded is True, result['tweets'] will contain a list of tweets.
    succeeded, result = twis.get_user_tweets(auth_secret, 'username', -1)

    # Follow a user.
    succeeded, result = twis.follow(auth_secret, 'followee_username')

    # Unfollow a user.
    succeeded, result = twis.unfollow(auth_secret, 'followee_username')

    # Get the follower list. If succeeded is True, result['follower_list'] will contain the follower list.
    succeeded, result = twis.get_followers(auth_secret)

    # Get the following list. If succeeded is True, result['following_list'] will contain the following list.
    succeeded, result = twis.get_followings(auth_secret)

    # Change the user password. If succeeded is True, result['auth'] will contain the new authentication secret.
    succeeded, result = twis.change_password(auth_secret, 'password', 'new_password')

    # Get the user profile. If succeeded is True, result['username'] will contain the username, result['password'] 
    # will contain the password, and result['auth'] will contain the authentication secret.
    succeeded, result = twis.get_user_profile(auth_secret)

    # Log out of the user.
    succeeded, result = twis.logout(auth_secret)

2. ``pytwis_clt``
-----------------

After you install the package, you will be able to launch ``pytwis_clt``
as a console command. To get the help information,

.. code:: bash

    $ pytwis_clt -h
    $ pytwis_clt --help

2.1. Connect to Redis
~~~~~~~~~~~~~~~~~~~~~

2.1.1. Connect to the local Redis server at the default port 6379 with
no password.

.. code:: bash

    $ ./pytwis_clt.py 

2.1.2. Connect to the local Redis server via the socket file
``/tmp/redis.sock`` with password zzzzzz. Make sure that the unixsocket
parameter is defined in your redis.conf file. It’s commented out by
default.

.. code:: bash

    $ ./pytwis_clt.py -s /tmp/redis.sock -a zzzzzz

2.1.3 Connect to a remote Redis server with IP = xxx.xxx.xxx.xxx at port
yyyy with password zzzzzz.

.. code:: bash

    $ ./pytwis_clt.py -h xxx.xxx.xxx.xxx -p yyyy -a zzzzzz

2.2. Available commands
~~~~~~~~~~~~~~~~~~~~~~~

After successfully connecting to the twitter clone, you can try the
following commands in ``pytwis_clt``.

2.2.1. ``register``

Register a new user ``xxxxxx`` with password ``yyyyyy``.

.. code:: bash

    127.0.0.1:6379> register xxxxxx yyyyyy

2.2.2. ``login``

Log into a user ``xxxxxxx`` with password ``yyyyyy``.

.. code:: bash

    127.0.0.1:6379> login xxxxxx yyyyyy

2.2.3. ``logout``

Log out of the current user.

.. code:: bash

    127.0.0.1:6379> logout

2.2.4. ``changepwd``

Change the password. Assume that the old password is ``yyyyyy`` and the
new password is ``zzzzzz``.

.. code:: bash

    127.0.0.1:6379> changepwd yyyyyy zzzzzz zzzzzz

2.2.5. ``userprofile``

Get the profile of the currently logged-in user.

.. code:: bash

    127.0.0.1:6379> userprofile

2.2.6. ``follow``

Follow a user ``xxxxxx``.

.. code:: bash

    127.0.0.1:6379> follow xxxxxx

2.2.7. ``unfollow``

Unfollow a user ``xxxxxx``.

.. code:: bash

    127.0.0.1:6379> unfollow xxxxxx

2.2.8. ``followers``

Get the follower list of the current user.

.. code:: bash

    127.0.0.1:6379> followers

2.2.9. ``followings``

Get the following list of the current user.

.. code:: bash

    127.0.0.1:6379> followings

2.2.10. ``post``

Post a tweet.

.. code:: bash

    127.0.0.1:6379> post <tweet>

2.2.11. ``timeline``

Get the general/user timeline. It will return the user timeline if a
user is logged in and will return the general timeline otherwise. Also,
it will return all the tweets in the timeline if max-tweet-count is not
specified.

.. code:: bash

    127.0.0.1:6379> timeline [max-tweet-count]

2.2.12. ``tweetsby``

Get the tweets posted by a user. It will return the tweets posted by the
current logged-in user if no username is specified. Also, it will return
all the tweets posted by the user if max-tweet-count is not specified.

.. code:: bash

    127.0.0.1:6379> tweetsby [username] [max-tweet-count]

2.2.13. ``exit`` or ``quit``

Exit the console program.

.. code:: bash

    127.0.0.1:6379> exit
    127.0.0.1:6379> quit

Note that some of the above commands have to be executed after a
successful log-in.

-  logout
-  changepassword
-  userprofile
-  follow
-  unfollow
-  followers
-  followings
-  post
-  tweetsby

3. Unit test
------------

Since this unit test requires a running local Redis server, it is in
fact a small integration test. To run the test,

.. code:: bash

    $ make test

4. Documentation
----------------

4.1. ``Sphinx``
~~~~~~~~~~~~~~~

To generate the ``Sphinx`` HTML documentation,

.. code:: bash

    $ make docs

4.2. README.rst
~~~~~~~~~~~~~~~

README.rst is generated from README.md via ``pandoc``.

.. code:: bash

    $ pandoc --from=markdown --to=rst --output=README.rst README.md
