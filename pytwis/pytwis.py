# -*- coding: utf-8 -*-
"""pytwis -- A Twitter-toy-clone backend using Python and Redis.

This module implements the backend for a simplified Twitter clone based on Redis.
We follow the Redis tutorial (https://redis.io/topics/twitter-clone) to design
the data layout of the Redis database.

It supports the following features:

-  Register new users
-  Log in/out
-  Change user password
-  Post tweets
-  Follower/Following
-  General timeline for anonymous user
-  User timeline
-  Get tweets posted by a user

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
"""

import re
import secrets
import time
from werkzeug.security import generate_password_hash, check_password_hash
import redis
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError
from redis.exceptions import WatchError

if __package__:
    # If this module is imported as part of the pytwis package, then use
    # the relative import.
    from . import pytwis_constants
else:
    # If this module is imported locally, e.g., by the script pytwis_clt.py,
    # then don't use the relative import.
    import pytwis_constants  # pylint: disable=import-error


class Pytwis:
    """This class implements all the interfaces to the Redis database of the Twitter-toy-clone."""

    def __init__(self, hostname='127.0.0.1', port=6379, socket='', db=0, password=''):
        """Initialize the class Pytiws.

        Parameters
        ----------
        hostname : str, optional
            The Redis server hostname which is usually an IP address (default: 127.0.0.1).
        port : int, optional
            The Redis server port number (default: 6379).
        socket: str, optional
            The Redis server socket which will override hostname and port if it is given.
        db : int, optional
            The selected Redis database index (default: 0).
        password : str, optional
            The Redis server password (default: '').

        Raises
        ------
        ValueError
            If failed to connect to the Redis server with either ResponseError or RedisTimeoutError.
        """
        if socket:
            self._rc = redis.StrictRedis(
                unix_socket_path=socket,
                db=db,
                password=password,
                decode_responses=True,  # Decode the response bytes into strings.
                socket_connect_timeout=pytwis_constants.REDIS_SOCKET_CONNECT_TIMEOUT)
        else:
            self._rc = redis.StrictRedis(
                host=hostname,
                port=port,
                db=db,
                password=password,
                decode_responses=True,  # Decode the response bytes into strings.
                socket_connect_timeout=pytwis_constants.REDIS_SOCKET_CONNECT_TIMEOUT)

        # Test the connection by ping.
        try:
            if self._rc.ping():
                if socket:
                    print('Ping {} returned True'.format(socket))
                else:
                    print('Ping {}:{} returned True'.format(hostname, port))
        except (ResponseError, RedisTimeoutError) as excep:
            raise ValueError(str(excep))

    def _is_loggedin(self, auth_secret):
        """Check if a user is logged-in by verifying the input authentication secret.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of a logged-in user.

        Returns
        -------
        bool
            True if the authentication secret is valid, False otherwise.
        userid: str
            The user ID associated with the authentication secret if the authentication secret
            valid, None otherwise.
        """
        # Get the userid from the authentication secret.
        userid = self._rc.hget(pytwis_constants.AUTHS_KEY, auth_secret)
        if userid is None:
            return (False, None)

        # Compare the input authentication secret with the stored one.
        userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_auth_secret = self._rc.hget(userid_profile_key, pytwis_constants.AUTH_KEY)
        if auth_secret == stored_auth_secret:
            return (True, userid)

        # TODO: Resolve the inconsistency of the two authentication secrets.
        return (False, None)

    @staticmethod
    def _check_username(username):
        """Check if a username is valid.
        A username is considered valid if:
            3 characters length or more
            each character can only be letter (either uppercase or lowercase), digit, '_', or '-'
            the first character is a letter

        Parameters
        ----------
        username: str

        Returns
        -------
        bool
            True if the username is valid, False otherwise.
        """
        return re.match(r'^[A-Za-z][A-Za-z0-9_-]{2,}$', username) is not None

    @staticmethod
    def _check_password(password):
        """Check the strength of a password.
        A password is considered strong if
            8 characters length or more
            1 digit or more
            1 uppercase letter or more
            1 lowercase letter or more
            1 symbol (excluding whitespace characters) or more

        Parameters
        ----------
        password: str

        Returns
        -------
        bool
            True if the password is strong enough, False otherwise.
        """
        # Check the length.
        length_error = len(password) < 8

        # Search for digits.
        digit_error = re.search(r'\d', password) is None

        # Search for uppercase letters.
        uppercase_error = re.search(r'[A-Z]', password) is None

        # Search for lowercase letters.
        lowercase_error = re.search(r'[a-z]', password) is None

        # Search for symbols (excluding whitespace characters).
        symbol_error = re.search(r'[^A-Za-z\d\s]', password) is None

        return not (length_error or digit_error or uppercase_error or\
                    lowercase_error or symbol_error)

    def register(self, username, password):
        """Register a new user.

        Parameters
        ----------
        username: str
            The username.
        password: str
            The password.

        Returns
        -------
        bool
            True if the new user is successfully registered, False otherwise.
        result
            An empty dict if the new user is successfully registered, a dict
            containing the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_USERNAME_ALREADY_EXISTS.format(username)
        -  ERROR_WEAK_PASSWORD
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check the username.
        if not Pytwis._check_username(username):
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_INVALID_USERNAME
            return (False, result)

        # Check the password.
        if not Pytwis._check_password(password):
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_WEAK_PASSWORD
            return (False, result)

        # Update the username-to-userid mapping.
        with self._rc.pipeline() as pipe:
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that
                    # multiple clients are registering with the same username.
                    pipe.watch(pytwis_constants.USERS_KEY)
                    username_exists = pipe.hexists(pytwis_constants.USERS_KEY, username)
                    if username_exists:
                        result[pytwis_constants.ERROR_KEY] = \
                            pytwis_constants.ERROR_USERNAME_ALREADY_EXISTS.format(username)
                        return (False, result)

                    # Get the next user-id. If the key "next_user_id" doesn't exist,
                    # it will be created and initialized as 0, and then incremented by 1.
                    userid = pipe.incr(pytwis_constants.NEXT_USER_ID_KEY)

                    # Set the username-to-userid pair in USERS_HASH_KEY.
                    pipe.multi()
                    pipe.hset(pytwis_constants.USERS_KEY, username, userid)
                    pipe.execute()

                    break
                except WatchError:
                    continue

            # Generate the authentication secret.
            auth_secret = secrets.token_hex()
            userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)

            # Generate the password hash.
            # The format of the password hash looks like "method$salt$hash".
            password_hash = generate_password_hash(password,
                                                   method=\
                                                   pytwis_constants.PASSWORD_HASH_METHOD)

            pipe.multi()
            # Update the authentication_secret-to-userid mapping.
            pipe.hset(pytwis_constants.AUTHS_KEY, auth_secret, userid)
            # Create the user profile.
            pipe.hmset(userid_profile_key,
                       {pytwis_constants.USERNAME_KEY: username,
                        pytwis_constants.PASSWORD_HASH_KEY: password_hash,
                        pytwis_constants.AUTH_KEY: auth_secret})
            pipe.execute()

        return (True, result)

    def change_password(self, auth_secret, old_password, new_password):
        """Change the user password.

        Parameters
        ----------
        auth_secret: str
            The authentication secret which will be used for user authentication.
        old_password: str
            The old password before the change.
        new_password: str
            The new password after the change.

        Returns
        -------
        bool
            True if the password is successfully changed, False otherwise.
        result
            A dict containing the new authentication secret with the key AUTH_KEY
            if the password is successfully changed, a dict containing the error
            string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NEW_PASSWORD_NO_CHANGE
        -  ERROR_NOT_LOGGED_IN
        -  ERROR_INCORRECT_OLD_PASSWORD
        -  ERROR_WEAK_PASSWORD
        """
        result = {pytwis_constants.ERROR_KEY: None}

        if old_password == new_password:
            result[pytwis_constants.ERROR_KEY] = \
                pytwis_constants.ERROR_NEW_PASSWORD_NO_CHANGE
            return (False, result)

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Check if the old password matches.
        userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_password_hash = self._rc.hget(userid_profile_key,
                                             pytwis_constants.PASSWORD_HASH_KEY)
        if not check_password_hash(stored_password_hash, old_password):
            result[pytwis_constants.ERROR_KEY] = \
                pytwis_constants.ERROR_INCORRECT_OLD_PASSWORD
            return (False, result)

        # Check the password.
        if not Pytwis._check_password(new_password):
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_WEAK_PASSWORD
            return (False, result)

        # Generate the new authentication secret.
        new_auth_secret = secrets.token_hex()

        # Generate the new password hash.
        # The format of the new password hash looks like "method$salt$hash".
        new_password_hash = generate_password_hash(new_password,
                                                   method=\
                                                   pytwis_constants.PASSWORD_HASH_METHOD)

        # Replace the old password hash by the new one and the old authentication secret
        # by the new one.
        with self._rc.pipeline() as pipe:
            pipe.multi()
            pipe.hset(userid_profile_key,
                      pytwis_constants.PASSWORD_HASH_KEY,
                      new_password_hash)
            pipe.hset(userid_profile_key, pytwis_constants.AUTH_KEY, new_auth_secret)
            pipe.hset(pytwis_constants.AUTHS_KEY, new_auth_secret, userid)
            pipe.hdel(pytwis_constants.AUTHS_KEY, auth_secret)
            pipe.execute()

        result[pytwis_constants.AUTH_KEY] = new_auth_secret
        return (True, result)

    def login(self, username, password):
        """Log into a user.

        Parameters
        ----------
        username: str
            The username.
        password: str
            The password.

        Returns
        -------
        bool
            True if the login is successful, False otherwise.
        result
            A dict containing the authentication secret with the key AUTH_KEY
            if the login is successful, a dict containing the error string
            with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
        -  ERROR_INCORRECT_PASSWORD
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Get the user-id based on the username.
        userid = self._rc.hget(pytwis_constants.USERS_KEY, username)
        if userid is None:
            result[pytwis_constants.ERROR_KEY] = \
                pytwis_constants.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
            return (False, result)

        # Compare the input password hash with the stored one. If it matches,
        # return the authentication secret.
        userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_password_hash = self._rc.hget(userid_profile_key,
                                             pytwis_constants.PASSWORD_HASH_KEY)
        if check_password_hash(stored_password_hash, password):
            result[pytwis_constants.AUTH_KEY] = \
                self._rc.hget(userid_profile_key, pytwis_constants.AUTH_KEY)
            return (True, result)

        result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_INCORRECT_PASSWORD
        return (False, result)

    def logout(self, auth_secret):
        """Log out of a user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.

        Returns
        -------
        bool
            True if the logout is successful, False otherwise.
        result
            None if the logout is successful, a dict containing the error string
            with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Generate the new authentication secret.
        new_auth_secret = secrets.token_hex()

        # Replace the old authentication secret by the new one.
        userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
        with self._rc.pipeline() as pipe:
            pipe.multi()
            pipe.hset(userid_profile_key, pytwis_constants.AUTH_KEY, new_auth_secret)
            pipe.hset(pytwis_constants.AUTHS_KEY, new_auth_secret, userid)
            pipe.hdel(pytwis_constants.AUTHS_KEY, auth_secret)
            pipe.execute()

        result[pytwis_constants.USERNAME_KEY] = \
            self._rc.hget(userid_profile_key, pytwis_constants.USERNAME_KEY)
        result[pytwis_constants.AUTH_KEY] = ''
        return (True, result)

    def get_user_profile(self, auth_secret):
        """Get the profile (i.e., username, password, etc.) of a user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.

        Returns
        -------
        bool
            True if the logout is successful, False otherwise.
        result
            A dict containing the following keys:

            -  USERNAME_KEY
            -  PASSWORD_HASH_KEY
            -  AUTH_KEY

            if the user profile is obtained successfully; otherwise a dict
            containing the error string with the key ERROR_KEY.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = \
                pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        userid_profile_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
        result = self._rc.hgetall(userid_profile_key)

        return (True, result)

    def post_tweet(self, auth_secret, tweet):
        """Post a tweet.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.
        tweet: str
            The tweet that will be posted.

        Returns
        -------
        bool
            True if the tweet is successfully posted, False otherwise.
        result
            None if the tweet is successfully posted, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Get the next user-id. If the key "next_user_id" doesn't exist,
        # it will be created and initialized as 0, and then incremented by 1.
        post_id = self._rc.incr(pytwis_constants.NEXT_TWEET_ID_KEY)
        post_id_key = pytwis_constants.TWEET_KEY_FORMAT.format(post_id)

        post_id_timeline_key = pytwis_constants.USER_TIMELINE_KEY_FORMAT.format(userid)
        post_id_user_key = pytwis_constants.USER_TWEETS_KEY_FORMAT.format(userid)

        follower_zset_key = pytwis_constants.FOLLOWER_KEY_FORMAT.format(userid)
        followers = self._rc.zrange(follower_zset_key, 0, -1)

        unix_time = int(time.time())
        with self._rc.pipeline() as pipe:
            pipe.multi()
            # Store the tweet with its user ID and UNIX timestamp.
            pipe.hmset(post_id_key,
                       {pytwis_constants.TWEET_USERID_KEY: userid,
                        pytwis_constants.TWEET_UNIXTIME_KEY: unix_time,
                        pytwis_constants.TWEET_BODY_KEY: tweet})

            # Add the tweet to the user timeline.
            pipe.lpush(post_id_timeline_key, post_id)

            # Add the tweet to the tweet list posted by the user.
            pipe.lpush(post_id_user_key, post_id)

            # Write fanout the tweet to all the followers' timelines.
            for follower in followers:
                post_id_follower_key = \
                    pytwis_constants.USER_TIMELINE_KEY_FORMAT.format(follower)
                pipe.lpush(post_id_follower_key, post_id)

            # Add the tweet to the general timeline and left trim the general timeline
            # to only retain the latest GENERAL_TIMELINE_LIST_MAX_TWEET_CNT tweets.
            pipe.lpush(pytwis_constants.GENERAL_TIMELINE_KEY, post_id)
            pipe.ltrim(pytwis_constants.GENERAL_TIMELINE_KEY,
                       0,
                       pytwis_constants.GENERAL_TIMELINE_MAX_TWEET_CNT - 1)

            pipe.execute()

        return (True, result)

    def follow(self, auth_secret, followee_username):
        """Follow a user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.
        followee_username: str
            The username of the followee.

        Returns
        -------
        bool
            True if the follow is successful, False otherwise.
        result
            None if the follow is successful, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        -  ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
        -  ERROR_FOLLOW_YOURSELF_FORMAT.format(followee_username)
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        with self._rc.pipeline() as pipe:
            # Check if the followee exists.
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that
                    # other clients are modifying the Hash 'users'.
                    pipe.watch(pytwis_constants.USERS_KEY)
                    followee_userid = pipe.hget(pytwis_constants.USERS_KEY, followee_username)
                    if followee_userid is None:
                        result[pytwis_constants.ERROR_KEY] = \
                            pytwis_constants.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.\
                                            format(followee_username)
                        return (False, result)
                    elif followee_userid == userid:
                        result[pytwis_constants.ERROR_KEY] = \
                            pytwis_constants.ERROR_FOLLOW_YOURSELF_FORMAT.format(followee_username)
                        return (False, result)

                    break
                except WatchError:
                    continue

            # Update the two zset 'followers:[followee_username]' and 'following:[username]'.
            follower_zset_key = pytwis_constants.FOLLOWER_KEY_FORMAT.format(followee_userid)
            following_zset_key = pytwis_constants.FOLLOWING_KEY_FORMAT.format(userid)
            unix_time = int(time.time())
            pipe.multi()
            pipe.zadd(follower_zset_key, unix_time, userid)
            pipe.zadd(following_zset_key, unix_time, followee_userid)
            pipe.execute()

        return (True, result)

    def unfollow(self, auth_secret, followee_username):
        """Unfollow a user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.
        followee_username: str
            The username of the followee.

        Returns
        -------
        bool
            True if the unfollow is successful, False otherwise.
        result
            None if the unfollow is successful, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        -  ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        with self._rc.pipeline() as pipe:
            # Check if the followee exists.
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that
                    # other clients are modifying the Hash 'users'.
                    pipe.watch(pytwis_constants.USERS_KEY)
                    followee_userid = pipe.hget(pytwis_constants.USERS_KEY, followee_username)
                    if followee_userid is None:
                        result[pytwis_constants.ERROR_KEY] = \
                            pytwis_constants.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.\
                                format(followee_username)
                        return (False, result)

                    break
                except WatchError:
                    continue

            # Remove followee_userid from the zset 'following:[username]' and remove userid
            # from the zset 'followers:[followee_username]'.
            follower_zset_key = pytwis_constants.FOLLOWER_KEY_FORMAT.format(followee_userid)
            following_zset_key = pytwis_constants.FOLLOWING_KEY_FORMAT.format(userid)
            pipe.multi()
            pipe.zrem(follower_zset_key, userid)
            pipe.zrem(following_zset_key, followee_userid)
            pipe.execute()

        return (True, result)

    def get_followers(self, auth_secret):
        """Get the follower list of a logged-in user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.

        Returns
        -------
        bool
            True if the follower list is successfully obtained, False otherwise.
        result
            A dict containing the follower list with the key FOLLOWER_LIST_KEY
            if the follower list is successfully obtained, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Get the list of followers' userids.
        follower_zset_key = pytwis_constants.FOLLOWER_KEY_FORMAT.format(userid)
        follower_userids = self._rc.zrange(follower_zset_key, 0, -1)

        if follower_userids is None or not follower_userids:
            result[pytwis_constants.FOLLOWER_LIST_KEY] = []
            return (True, result)

        # Get the list of followers' usernames from their userids.
        with self._rc.pipeline() as pipe:
            pipe.multi()

            for follower_userid in follower_userids:
                follower_userid_profile_key = \
                    pytwis_constants.USER_PROFILE_KEY_FORMAT.format(follower_userid)
                pipe.hget(follower_userid_profile_key, pytwis_constants.USERNAME_KEY)

            result[pytwis_constants.FOLLOWER_LIST_KEY] = pipe.execute()

        return (True, result)

    def get_following(self, auth_secret):
        """Get the following list of a logged-in user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.

        Returns
        -------
        bool
            True if the following list is successfully obtained, False otherwise.
        result
            A dict containing the following list with the key FOLLOWING_LIST_KEY
            if the follower list is successfully obtained, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Get the list of followers' userids.
        following_zset_key = pytwis_constants.FOLLOWING_KEY_FORMAT.format(userid)
        following_userids = self._rc.zrange(following_zset_key, 0, -1)

        if following_userids is None or not following_userids:
            result[pytwis_constants.FOLLOWING_LIST_KEY] = []
            return (True, result)

        # Get the list of followings' usernames from their userids.
        with self._rc.pipeline() as pipe:
            pipe.multi()

            for following_userid in following_userids:
                following_userid_profile_key = \
                    pytwis_constants.USER_PROFILE_KEY_FORMAT.format(following_userid)
                pipe.hget(following_userid_profile_key, pytwis_constants.USERNAME_KEY)

            result[pytwis_constants.FOLLOWING_LIST_KEY] = pipe.execute()

        return (True, result)

    def _get_tweets(self, tweets_key, max_cnt_tweets):
        """Get at most `max_cnt_tweets` tweets from the Redis list `tweets_key`.

        Parameters
        ----------
        tweets_key: str
            The key of the Redis list which stores the tweets.
        max_cnt_tweets: int
            The maximum number of tweets included in the returned list. If it is set to -1,
            then all the available tweets will be included.

        Returns
        -------
        tweets
            A list of tweets
        """
        tweets = []
        if max_cnt_tweets == 0:
            return tweets
        elif max_cnt_tweets == -1:
            # Return all the tweets in the timeline.
            last_tweet_index = -1
        else:
            # Return at most max_cnt_tweets tweets.
            last_tweet_index = max_cnt_tweets - 1

        # Get the post IDs of the tweets.
        post_ids = self._rc.lrange(tweets_key, 0, last_tweet_index)

        if not post_ids:
            return tweets

        with self._rc.pipeline() as pipe:
            # Get the tweets with their user IDs and UNIX timestamps.
            pipe.multi()
            for post_id in post_ids:
                post_id_key = pytwis_constants.TWEET_KEY_FORMAT.format(post_id)
                pipe.hgetall(post_id_key)
            tweets = pipe.execute()

            # Get the userid-to-username mappings for all the user IDs associated with the tweets.
            userid_set = {tweet[pytwis_constants.TWEET_USERID_KEY] for tweet in tweets}
            userid_list = []
            pipe.multi()
            for userid in userid_set:
                userid_list.append(userid)
                userid_key = pytwis_constants.USER_PROFILE_KEY_FORMAT.format(userid)
                pipe.hget(userid_key, pytwis_constants.USERNAME_KEY)
            username_list = pipe.execute()

        userid_to_username = {userid: username for userid, username in\
                              zip(userid_list, username_list)}

        # Add the username for the user ID of each tweet.
        for tweet in tweets:
            tweet[pytwis_constants.USERNAME_KEY] = \
                userid_to_username[tweet[pytwis_constants.TWEET_USERID_KEY]]

        return tweets

    def get_timeline(self, auth_secret, max_cnt_tweets):
        """Get the general or user timeline.

        If an empty authentication secret is given, this method returns the general timeline.
        If an authentication secret is given and it is valid, this method returns the user timeline.
        If an authentication secret is given but it is invalid, this method returns an error.

        Parameters
        ----------
        auth_secret: str
            Either the authentication secret of the logged-in user or an empty string.
        max_cnt_tweets: int
            The maximum number of tweets included in the timeline. If it is set to -1,
            then all the available tweets will be included.

        Returns
        -------
        bool
            True if the timeline is successfully retrieved, False otherwise.
        result
            A dict containing a list of tweets with the key TWEETS_KEY if
            the timeline is successfully retrieved, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        """
        result = {pytwis_constants.ERROR_KEY: None}

        if auth_secret == '':
            # An empty authentication secret implies getting the general timeline.
            timeline_key = pytwis_constants.GENERAL_TIMELINE_KEY
        else:
            # Check if the user is logged in.
            loggedin, userid = self._is_loggedin(auth_secret)
            if not loggedin:
                result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
                return (False, result)

            # Get the user timeline.
            timeline_key = pytwis_constants.USER_TIMELINE_KEY_FORMAT.format(userid)

        result[pytwis_constants.TWEETS_KEY] = self._get_tweets(timeline_key, max_cnt_tweets)
        return (True, result)

    def get_user_tweets(self, auth_secret, username, max_cnt_tweets):
        """Get the tweets posted by one user.

        Parameters
        ----------
        auth_secret: str
            The authentication secret of the logged-in user.
        username:
            The name of the user who post the tweets and may not be the logged-in user.
        max_cnt_tweets: int
            The maximum number of tweets included in the return. If it is set to -1,
            then all the tweets posted by the user will be included.

        Returns
        -------
        bool
            True if the tweets are successfully retrieved, False otherwise.
        result
            A dict containing a list of tweets with the key TWEETS_KEY if
            the tweets are successfully retrieved, a dict containing
            the error string with the key ERROR_KEY otherwise.

        Note
        ----
        Possible error strings are listed as below:

        -  ERROR_NOT_LOGGED_IN
        -  ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
        """
        result = {pytwis_constants.ERROR_KEY: None}

        # Check if the user is logged in.
        loggedin, _ = self._is_loggedin(auth_secret)
        if not loggedin:
            result[pytwis_constants.ERROR_KEY] = pytwis_constants.ERROR_NOT_LOGGED_IN
            return (False, result)

        # Get the userid from the username.
        userid = self._rc.hget(pytwis_constants.USERS_KEY, username)
        if userid is None:
            result[pytwis_constants.ERROR_KEY] = \
                pytwis_constants.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
            return (False, result)

        # Get the tweets posted by the user.
        user_tweets_key = pytwis_constants.USER_TWEETS_KEY_FORMAT.format(userid)

        result[pytwis_constants.TWEETS_KEY] = \
            self._get_tweets(user_tweets_key, max_cnt_tweets)
        return (True, result)
