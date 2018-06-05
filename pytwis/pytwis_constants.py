# -*- coding: utf-8 -*-
"""This module defines all the constants used by pytwis.py."""

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
