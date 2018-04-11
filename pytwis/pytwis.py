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
import redis
from redis.exceptions import (ResponseError, TimeoutError, WatchError)
import secrets
import time
from werkzeug.security import generate_password_hash, check_password_hash


class PytwisConstant:
    """This class defines all the constants used by pytwis.py."""
    REDIS_SOCKET_CONNECT_TIMEOUT = 60
    PASSWORD_HASH_METHOD = 'pbkdf2:sha512'
    
    NEXT_USER_ID_KEY = 'next_user_id'
    
    USERS_KEY = 'users'
    
    USER_PROFILE_KEY_FORMAT = 'user:{}'
    USERNAME_KEY = 'username'
    PASSWORD_HASH_KEY = 'password_hash'
    AUTH_KEY = 'auth'
    
    AUTHS_KEY = 'auths'
    
    FOLLOWER_KEY_FORMAT = 'follower:{}'
    FOLLOWING_KEY_FORMAT = 'following:{}'
    
    NEXT_TWEET_ID_KEY = 'next_tweet_id'
    
    TWEET_KEY_FORMAT = 'tweet:{}'
    TWEET_USERID_KEY = 'userid'
    TWEET_UNIXTIME_KEY = 'unix_time'
    TWEET_BODY_KEY = 'body'
    
    GENERAL_TIMELINE_KEY = 'timeline'
    GENERAL_TIMELINE_MAX_TWEET_CNT = 1000
    
    USER_TIMELINE_KEY_FORMAT = 'timeline:{}'
    
    USER_TWEETS_KEY_FORMAT = 'tweets_by:{}'
    
    ERROR_KEY = 'error'
    FOLLOWER_LIST_KEY = 'follower_list'
    FOLLOWING_LIST_KEY = 'following_list'
    TWEETS_KEY = 'tweets'
    
    ERROR_USERNAME_NOT_EXIST_FORMAT = "username {} doesn't exist"
    ERROR_USERNAME_ALREADY_EXISTS = 'username {} already exists'
    ERROR_INVALID_USERNAME = '''Invalid username. A valid username must 
                             * have 3 characters more;
                             * have only letters (either uppercase or lowercase), digits, '_', or '-';
                             * start with a letter.
                             '''
    ERROR_NOT_LOGGED_IN = 'Not logged in'
    ERROR_INCORRECT_PASSWORD = 'Incorrect password'
    ERROR_INCORRECT_OLD_PASSWORD = 'Incorrect old password'
    ERROR_NEW_PASSWORD_NO_CHANGE = 'New password same as old one'
    ERROR_WEAK_PASSWORD = '''Weak password. A strong password must have 
                          * 8 characters or more;
                          * 1 digit or more;
                          * 1 uppercase letter or more;
                          * 1 lowercase letter or more;
                          * 1 symbol (excluding whitespace characters) or more.
                          '''
    ERROR_FOLLOWEE_NOT_EXIST_FORMAT = "Followee {} doesn't exist"
    ERROR_FOLLOW_YOURSELF_FORMAT = "Can't follow yourself {}"


class Pytwis:
    """This class implements all the interfaces to the Redis database of the Twitter-toy-clone."""
    
    def __init__(self, hostname='127.0.0.1', port=6379, socket='', db=0, password =''):
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
            If failed to connect to the Redis server with either ResponseError or TimeoutError.
        """
        if len(socket) > 0:
            self._rc = redis.StrictRedis(
                unix_socket_path=socket,
                db=db,
                password=password,
                decode_responses=True, # Decode the response bytes into strings.
                socket_connect_timeout=PytwisConstant.REDIS_SOCKET_CONNECT_TIMEOUT)
        else:
            self._rc = redis.StrictRedis(
                host=hostname,
                port=port,
                db=db,
                password=password,
                decode_responses=True, # Decode the response bytes into strings.
                socket_connect_timeout=PytwisConstant.REDIS_SOCKET_CONNECT_TIMEOUT)
        
        # Test the connection by ping.
        try:
            if self._rc.ping() == True:
                if len(socket) > 0:
                    print('Ping {} returned True'.format(socket))
                else:
                    print('Ping {}:{} returned True'.format(hostname, port))
        except (ResponseError, TimeoutError) as e:
            raise ValueError(str(e)) from e
        
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
        userid = self._rc.hget(PytwisConstant.AUTHS_KEY, auth_secret)
        if userid is None:
            return (False, None)
        
        # Compare the input authentication secret with the stored one.
        userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_auth_secret = self._rc.hget(userid_profile_key, PytwisConstant.AUTH_KEY)
        if auth_secret == stored_auth_secret:
            return (True, userid)
        else:
            # TODO: Resolve the inconsistency of the two authentication secrets. 
            return (False, None)
            
    def _check_username(self, username):
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
    
    def _check_password(self, password):
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
        
        return not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

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
            containing the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_USERNAME_ALREADY_EXISTS.format(username)
        -  PytwisConstant.ERROR_WEAK_PASSWORD
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check the username.
        if not self._check_username(username):
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_INVALID_USERNAME
            return (False, result)      
        
        # Check the password.
        if not self._check_password(password):
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_WEAK_PASSWORD
            return (False, result)

        # Update the username-to-userid mapping.
        with self._rc.pipeline() as pipe:
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that 
                    # multiple clients are registering with the same username.
                    pipe.watch(PytwisConstant.USERS_KEY)
                    username_exists = pipe.hexists(PytwisConstant.USERS_KEY, username)
                    if username_exists:
                        result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_USERNAME_ALREADY_EXISTS.format(username)
                        return (False, result);
                    
                    # Get the next user-id. If the key "next_user_id" doesn't exist,
                    # it will be created and initialized as 0, and then incremented by 1.
                    userid = pipe.incr(PytwisConstant.NEXT_USER_ID_KEY)
                    
                    # Set the username-to-userid pair in USERS_HASH_KEY.
                    pipe.multi()
                    pipe.hset(PytwisConstant.USERS_KEY, username, userid)
                    pipe.execute()
                    
                    break
                except WatchError:
                    continue
                
            # Generate the authentication secret.
            auth_secret = secrets.token_hex()
            userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
            
            # Generate the password hash.
            # The format of the password hash looks like "method$salt$hash". 
            password_hash = generate_password_hash(password, method=PytwisConstant.PASSWORD_HASH_METHOD)
            
            pipe.multi()
            # Update the authentication_secret-to-userid mapping.
            pipe.hset(PytwisConstant.AUTHS_KEY, auth_secret, userid)
            # Create the user profile.
            pipe.hmset(userid_profile_key, 
                       {PytwisConstant.USERNAME_KEY: username, 
                        PytwisConstant.PASSWORD_HASH_KEY: password_hash,
                        PytwisConstant.AUTH_KEY: auth_secret})
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
            A dict containing the new authentication secret with the key PytwisConstant.AUTH_KEY 
            if the password is successfully changed, a dict containing the error 
            string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NEW_PASSWORD_NO_CHANGE
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        -  PytwisConstant.ERROR_INCORRECT_OLD_PASSWORD
        -  PytwisConstant.ERROR_WEAK_PASSWORD
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        if old_password == new_password:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NEW_PASSWORD_NO_CHANGE
            return (False, result)
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Check if the old password matches.
        userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_password_hash = self._rc.hget(userid_profile_key, PytwisConstant.PASSWORD_HASH_KEY)
        if not check_password_hash(stored_password_hash, old_password):
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_INCORRECT_OLD_PASSWORD
            return (False, result)
        
        # Check the password.
        if not self._check_password(new_password):
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_WEAK_PASSWORD
            return (False, result)
        
        # Generate the new authentication secret.
        new_auth_secret = secrets.token_hex()
        
        # Generate the new password hash.
        # The format of the new password hash looks like "method$salt$hash".
        new_password_hash = generate_password_hash(new_password, method=PytwisConstant.PASSWORD_HASH_METHOD)
        
        # Replace the old password hash by the new one and the old authentication secret by the new one.
        with self._rc.pipeline() as pipe:
            pipe.multi()
            pipe.hset(userid_profile_key, PytwisConstant.PASSWORD_HASH_KEY, new_password_hash)
            pipe.hset(userid_profile_key, PytwisConstant.AUTH_KEY, new_auth_secret)
            pipe.hset(PytwisConstant.AUTHS_KEY, new_auth_secret, userid)
            pipe.hdel(PytwisConstant.AUTHS_KEY, auth_secret)
            pipe.execute()
        
        result[PytwisConstant.AUTH_KEY] = new_auth_secret
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
            A dict containing the authentication secret with the key PytwisConstant.AUTH_KEY 
            if the login is successful, a dict containing the error string 
            with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
        -  PytwisConstant.ERROR_INCORRECT_PASSWORD
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Get the user-id based on the username.
        userid = self._rc.hget(PytwisConstant.USERS_KEY, username)
        if userid is None:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
            return (False, result)
        
        # Compare the input password hash with the stored one. If it matches, 
        # return the authentication secret.
        userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
        stored_password_hash = self._rc.hget(userid_profile_key, PytwisConstant.PASSWORD_HASH_KEY)
        if check_password_hash(stored_password_hash, password):
            result[PytwisConstant.AUTH_KEY] = self._rc.hget(userid_profile_key, PytwisConstant.AUTH_KEY)
            return (True, result)
        else:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_INCORRECT_PASSWORD
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
            with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Generate the new authentication secret.
        new_auth_secret = secrets.token_hex()
        
        # Replace the old authentication secret by the new one.
        userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
        with self._rc.pipeline() as pipe:
            pipe.multi()
            pipe.hset(userid_profile_key, PytwisConstant.AUTH_KEY, new_auth_secret)
            pipe.hset(PytwisConstant.AUTHS_KEY, new_auth_secret, userid)
            pipe.hdel(PytwisConstant.AUTHS_KEY, auth_secret)
            pipe.execute()
            
        result[PytwisConstant.USERNAME_KEY] = self._rc.hget(userid_profile_key, PytwisConstant.USERNAME_KEY)
        result[PytwisConstant.AUTH_KEY] = ''
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
            
            if the user profile is obtained successfully; otherwise a dict containing the error string 
            with the key PytwisConstant.ERROR_KEY.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
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
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Get the next user-id. If the key "next_user_id" doesn't exist,
        # it will be created and initialized as 0, and then incremented by 1.
        post_id = self._rc.incr(PytwisConstant.NEXT_TWEET_ID_KEY)
        post_id_key = PytwisConstant.TWEET_KEY_FORMAT.format(post_id)
        
        post_id_timeline_key = PytwisConstant.USER_TIMELINE_KEY_FORMAT.format(userid)
        post_id_user_key = PytwisConstant.USER_TWEETS_KEY_FORMAT.format(userid)
        
        follower_zset_key = PytwisConstant.FOLLOWER_KEY_FORMAT.format(userid)
        followers = self._rc.zrange(follower_zset_key, 0, -1)
        
        unix_time = int(time.time())
        with self._rc.pipeline() as pipe:
            pipe.multi()
            # Store the tweet with its user ID and UNIX timestamp.
            pipe.hmset(post_id_key,
                       {PytwisConstant.TWEET_USERID_KEY: userid,
                        PytwisConstant.TWEET_UNIXTIME_KEY: unix_time,
                        PytwisConstant.TWEET_BODY_KEY: tweet})
            
            # Add the tweet to the user timeline.
            pipe.lpush(post_id_timeline_key, post_id)
            
            # Add the tweet to the tweet list posted by the user.
            pipe.lpush(post_id_user_key, post_id)
            
            # Write fanout the tweet to all the followers' timelines.
            for follower in followers:
                post_id_follower_key = PytwisConstant.USER_TIMELINE_KEY_FORMAT.format(follower)
                pipe.lpush(post_id_follower_key, post_id)
            
            # Add the tweet to the general timeline and left trim the general timeline to only retain 
            # the latest GENERAL_TIMELINE_LIST_MAX_TWEET_CNT tweets.
            pipe.lpush(PytwisConstant.GENERAL_TIMELINE_KEY, post_id)
            pipe.ltrim(PytwisConstant.GENERAL_TIMELINE_KEY, 0, PytwisConstant.GENERAL_TIMELINE_MAX_TWEET_CNT - 1)
            
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
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        -  PytwisConstant.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
        -  PytwisConstant.ERROR_FOLLOW_YOURSELF_FORMAT.format(followee_username)
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        with self._rc.pipeline() as pipe:
            # Check if the followee exists.
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that 
                    # other clients are modifying the Hash 'users'.
                    pipe.watch(PytwisConstant.USERS_KEY)
                    followee_userid = pipe.hget(PytwisConstant.USERS_KEY, followee_username)
                    if followee_userid is None:
                        result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
                        return (False, result);
                    elif followee_userid == userid:
                        result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_FOLLOW_YOURSELF_FORMAT.format(followee_username)
                        return (False, result)
                    
                    break
                except WatchError:
                    continue
            
            # Update the two zset 'followers:[followee_username]' and 'following:[username]'.
            follower_zset_key = PytwisConstant.FOLLOWER_KEY_FORMAT.format(followee_userid)
            following_zset_key = PytwisConstant.FOLLOWING_KEY_FORMAT.format(userid)
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
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        -  PytwisConstant.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        with self._rc.pipeline() as pipe:
            # Check if the followee exists.
            while True:
                try:
                    # Put a watch on the Hash 'users': username -> user-id, in case that 
                    # other clients are modifying the Hash 'users'.
                    pipe.watch(PytwisConstant.USERS_KEY)
                    followee_userid = pipe.hget(PytwisConstant.USERS_KEY, followee_username)
                    if followee_userid is None:
                        result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(followee_username)
                        return (False, result);
                    
                    break
                except WatchError:
                    continue
            
            # Remove followee_userid from the zset 'following:[username]' and remove userid 
            # from the zset 'followers:[followee_username]'.
            follower_zset_key = PytwisConstant.FOLLOWER_KEY_FORMAT.format(followee_userid)
            following_zset_key = PytwisConstant.FOLLOWING_KEY_FORMAT.format(userid)
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
            A dict containing the follower list with the key PytwisConstant.FOLLOWER_LIST_KEY 
            if the follower list is successfully obtained, a dict containing 
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Get the list of followers' userids.
        follower_zset_key = PytwisConstant.FOLLOWER_KEY_FORMAT.format(userid)
        follower_userids = self._rc.zrange(follower_zset_key, 0, -1)
        
        if follower_userids is None or len(follower_userids) == 0:
            result[PytwisConstant.FOLLOWER_LIST_KEY] = []
            return (True, result)
        
        # Get the list of followers' usernames from their userids.
        with self._rc.pipeline() as pipe:
            pipe.multi()
            
            for follower_userid in follower_userids:
                follower_userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(follower_userid)
                pipe.hget(follower_userid_profile_key, PytwisConstant.USERNAME_KEY)
            
            result[PytwisConstant.FOLLOWER_LIST_KEY] = pipe.execute()
            
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
            A dict containing the following list with the key PytwisConstant.FOLLOWING_LIST_KEY 
            if the follower list is successfully obtained, a dict containing 
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, userid = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Get the list of followers' userids.
        following_zset_key = PytwisConstant.FOLLOWING_KEY_FORMAT.format(userid)
        following_userids = self._rc.zrange(following_zset_key, 0, -1)
        
        if following_userids is None or len(following_userids) == 0:
            result[PytwisConstant.FOLLOWING_LIST_KEY] = []
            return (True, result)
        
        # Get the list of followings' usernames from their userids.
        with self._rc.pipeline() as pipe:
            pipe.multi()
            
            for following_userid in following_userids:
                following_userid_profile_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(following_userid)
                pipe.hget(following_userid_profile_key, PytwisConstant.USERNAME_KEY)
            
            result[PytwisConstant.FOLLOWING_LIST_KEY] = pipe.execute()
            
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
        
        if len(post_ids) == 0:
            return tweets
        
        with self._rc.pipeline() as pipe:
            # Get the tweets with their user IDs and UNIX timestamps.
            pipe.multi()
            for post_id in post_ids:
                post_id_key = PytwisConstant.TWEET_KEY_FORMAT.format(post_id)
                pipe.hgetall(post_id_key)
            tweets = pipe.execute()
        
            # Get the userid-to-username mappings for all the user IDs associated with the tweets.
            userid_set = { tweet[PytwisConstant.TWEET_USERID_KEY] for tweet in tweets }
            userid_list = []
            pipe.multi()
            for userid in userid_set:
                userid_list.append(userid)
                userid_key = PytwisConstant.USER_PROFILE_KEY_FORMAT.format(userid)
                pipe.hget(userid_key, PytwisConstant.USERNAME_KEY)
            username_list = pipe.execute()
        
        userid_to_username = { userid: username for userid, username in zip(userid_list, username_list) }
        
        # Add the username for the user ID of each tweet.
        for tweet in tweets:
            tweet[PytwisConstant.USERNAME_KEY] = userid_to_username[tweet[PytwisConstant.TWEET_USERID_KEY]]
    
        return tweets
    
    def get_timeline(self, auth_secret, max_cnt_tweets):
        """Get the general or user timeline. 
        
        If an empty authentication secret is given, this method will return the general timeline. 
        If an authentication secret is given and it is valid, this method will return the user timeline.
        If an authentication secret is given but it is invalid, this method will return an error. 
        
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
            A dict containing a list of tweets with the key PytwisConstant.TWEETS_KEY if 
            the timeline is successfully retrieved, a dict containing 
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        if auth_secret == '':
            # An empty authentication secret implies getting the general timeline.
            timeline_key = PytwisConstant.GENERAL_TIMELINE_KEY
        else:
            # Check if the user is logged in.
            loggedin, userid = self._is_loggedin(auth_secret)
            if not loggedin:
                result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
                return (False, result)
            
            # Get the user timeline.
            timeline_key = PytwisConstant.USER_TIMELINE_KEY_FORMAT.format(userid)
        
        result[PytwisConstant.TWEETS_KEY] = self._get_tweets(timeline_key, max_cnt_tweets)
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
            A dict containing a list of tweets with the key PytwisConstant.TWEETS_KEY if 
            the tweets are successfully retrieved, a dict containing 
            the error string with the key PytwisConstant.ERROR_KEY otherwise.
            
        Note
        ----
        Possible error strings are listed as below: 
        
        -  PytwisConstant.ERROR_NOT_LOGGED_IN
        -  PytwisConstant.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
        """
        result = {PytwisConstant.ERROR_KEY: None}
        
        # Check if the user is logged in.
        loggedin, _ = self._is_loggedin(auth_secret)
        if not loggedin:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_NOT_LOGGED_IN
            return (False, result)
        
        # Get the userid from the username.
        userid = self._rc.hget(PytwisConstant.USERS_KEY, username)
        if userid is None:
            result[PytwisConstant.ERROR_KEY] = PytwisConstant.ERROR_USERNAME_NOT_EXIST_FORMAT.format(username)
            return (False, result)
        
        # Get the tweets posted by the user.
        user_tweets_key = PytwisConstant.USER_TWEETS_KEY_FORMAT.format(userid)
        
        result[PytwisConstant.TWEETS_KEY] = self._get_tweets(user_tweets_key, max_cnt_tweets)
        return (True, result)
