#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A command-line tool which uses `pytwis` to interact with the Redis database of a Twitter toy clone.

To see the help information,

.. code:: bash

    $ ./pytwis_clt.py -h
    $ ./pytwis_clt.py --help
    
After launching `pytwis_clt.py`, you will be able to use the following commands:

* Register a new user:

.. code:: bash

    127.0.0.1:6379> register {username} {password} 

* Log into a user:

.. code:: bash

    127.0.0.1:6379> login {username} {password} 

* Log out of a user:

.. code:: bash

    127.0.0.1:6379> logout

* Change the password:

.. code:: bash

    127.0.0.1:6379> changepwd {old_password} {new_password} {confirmed_new_password}
    
* Get the profile of the current user:

.. code:: bash

    127.0.0.1:6379> userprofile

* Post a tweet:

.. code:: bash

    127.0.0.1:6379> post {tweet}

* Follow a user:

.. code:: bash

    127.0.0.1:6379> follow {followee_username}

* Unfollow a user:

.. code:: bash

    127.0.0.1:6379> unfollow {followee_username}

* Get the follower list:

.. code:: bash

    127.0.0.1:6379> followers

* Get the following list:

.. code:: bash

    127.0.0.1:6379> followings

* Get the timeline:

.. code:: bash

    127.0.0.1:6379> timeline
    127.0.0.1:6379> timeline {max_tweet_count}
    
Note that if a user is logged in, `timeline` will return the user timeline; 
otherwise `timeline` will return the general timeline.

* Get the tweets posted by a user:

.. code:: bash

    127.0.0.1:6379> tweetsby 
    127.0.0.1:6379> tweetsby {username}
    127.0.0.1:6379> tweetsby {username} {max_tweet_count}
    
Note that if no username is given, `tweetsby` will return the tweets posted 
by the currently logged-in user.

* Exit the program:

.. code:: bash

    127.0.0.1:6379> exit
    127.0.0.1:6379> quit

"""

import argparse
import datetime
import parse
import sys

from pytwis import PytwisConstant, Pytwis

class CmdConstant:
    """This class defines all the constants used by pytwis_clt.py."""
    CMD_REGISTER = 'register'
    CMD_LOGIN = 'login'
    CMD_LOGOUT = 'logout'
    CMD_CHANGE_PASSWORD = 'changepwd'
    CMD_GET_USER_PROFILE = 'userprofile'
    CMD_POST = 'post'
    CMD_FOLLOW = 'follow'
    CMD_UNFOLLOW = 'unfollow'
    CMD_GET_FOLLOWERS = 'followers'
    CMD_GET_FOLLOWINGS = 'followings'
    CMD_TIMELINE = 'timeline'
    CMD_GET_USER_TWEETS = 'tweetsby'
    CMD_EXIT = 'exit'
    CMD_QUIT = 'quit'


def validate_command(raw_command):
    """Validate the command input.
    
    Currently we only check the number of arguments according to the command type.
    
    Parameters
    ----------
    raw_command: str
        The raw command input, e.g., `register xxxxxx yyyyyy`.
        
    Raises
    ------
    ValueError
        If the raw command input doesn't have the correct number of arguments.
    """
    parsed_command = raw_command.split()
    arg_count = len(parsed_command) - 1

    if (len(parsed_command) == 0):
        return

    if (parsed_command[0] == CmdConstant.CMD_REGISTER):
        if (arg_count < 2):
            raise ValueError('{} {{username}} {{password}}'.format(CmdConstant.CMD_REGISTER))
    elif (parsed_command[0] == CmdConstant.CMD_LOGIN):
        if (arg_count < 2):
            raise ValueError('{} {{username}} {{password}}'.format(CmdConstant.CMD_LOGIN))
    elif (parsed_command[0] == CmdConstant.CMD_LOGOUT):
        pass
    elif (parsed_command[0] == CmdConstant.CMD_CHANGE_PASSWORD):
        if (arg_count < 3):
            raise ValueError('{} {{old_password}} {{new_password}} {{confirmed_new_password}}'.\
                             format(CmdConstant.CMD_CHANGE_PASSWORD))
    elif (parsed_command[0] == CmdConstant.CMD_GET_USER_PROFILE):
        pass
    elif (parsed_command[0] == CmdConstant.CMD_POST):
        if (arg_count < 1):
            raise ValueError('{} {{tweet}}'.format(CmdConstant.CMD_POST))
    elif (parsed_command[0] == CmdConstant.CMD_FOLLOW):
        if (arg_count < 1):
            raise ValueError('{} {{followee_username}}'.format(CmdConstant.CMD_FOLLOW))
    elif (parsed_command[0] == CmdConstant.CMD_UNFOLLOW):
        if (arg_count < 1):
            raise ValueError('{} {{followee_username}}'.format(CmdConstant.CMD_UNFOLLOW))
    elif (parsed_command[0] == CmdConstant.CMD_GET_FOLLOWERS):
        pass
    elif (parsed_command[0] == CmdConstant.CMD_GET_FOLLOWINGS):
        pass
    elif (parsed_command[0] == CmdConstant.CMD_TIMELINE):
        if (arg_count > 2):
            raise ValueError('{CMD} {{max_tweet count}} or {CMD}'.format(CMD=CmdConstant.CMD_TIMELINE))
    elif (parsed_command[0] == CmdConstant.CMD_GET_USER_TWEETS):
        if (arg_count > 3):
            raise ValueError('{CMD} {{username}} {{max_tweet count}} or {CMD} {{username}} or {CMD}'.\
                             format(CMD=CmdConstant.CMD_GET_USER_TWEETS))
    elif (parsed_command[0] == CmdConstant.CMD_EXIT) or (parsed_command[0] == CmdConstant.CMD_QUIT):
        pass
    else:
        raise ValueError('Invalid pytwis command')


def pytwis_command_parser(raw_command):
    """Parse the command input.
    
    Parameters
    ----------
    raw_command: str
        The raw command input, e.g., `register xxxxxx yyyyyy`.
        
    Returns
    -------
    command_with_args: list(str, dict(str, str or int))
        The parsed command output. The first element of the list is the command type, e.g., 'register', 
        and the second element is the command arguments, e.g., {'username': <username>, 'password': <password>} 
        for `register`.
    
    Raises
    ------
    ValueError
        If the raw command can't be parsed correctly, e.g., it has an incorrect number of arguments or 
        incorrect arguments.
    """
    # Separate the command from its arguments.
    splited_raw_command = raw_command.split(' ', 1)
    command_with_args = [splited_raw_command[0]]

    # Some command (e.g., logout) may not have arguments.
    arg_dict = {}

    validate_command(raw_command)

    if command_with_args[0] == CmdConstant.CMD_REGISTER:
        # register must have two arguments: username and password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.format(CmdConstant.CMD_REGISTER))
        elif ' ' in arg_dict['password']:
            raise ValueError("password can't contain spaces")

        print('{}: username = {}, password = {}'.format(CmdConstant.CMD_REGISTER, \
                                                        arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'login':
        # login must have two arguments: username and password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.format(CmdConstant.CMD_LOGIN))

        print('{}: username = {}, password = {}'.format(CmdConstant.CMD_LOGIN, \
                                                        arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == CmdConstant.CMD_LOGOUT:
        # logout doesn't have any arguments.
        pass
    elif command_with_args[0] == CmdConstant.CMD_CHANGE_PASSWORD:
        # changepwd must have three arguments: old_password, new_password, and confirmed_new_password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{old_password} {new_password} {confirmed_new_password}', args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.format(CmdConstant.CMD_CHANGE_PASSWORD))
        elif arg_dict['new_password'] != arg_dict['confirmed_new_password']:
            raise ValueError('The confirmed new password is different from the new password')
        elif arg_dict['new_password'] == arg_dict['old_password']:
            raise ValueError('The new password is the same as the old password')

        print('{}: old = {}, new = {}'.format(CmdConstant.CMD_CHANGE_PASSWORD, \
                                              arg_dict['old_password'], arg_dict['new_password']))
    elif command_with_args[0] == CmdConstant.CMD_GET_USER_PROFILE:
        # userprofile doesn't have any arguments.
        pass
    elif command_with_args[0] == CmdConstant.CMD_POST:
        # post must have one argument: tweet
        arg_dict = {'tweet': splited_raw_command[1]}
    elif command_with_args[0] == CmdConstant.CMD_FOLLOW:
        # follow must have one argument: followee.
        arg_dict = {'followee': splited_raw_command[1]}
    elif command_with_args[0] == CmdConstant.CMD_UNFOLLOW:
        # unfollow must have one argument: followee.
        arg_dict = {'followee': splited_raw_command[1]}
    elif command_with_args[0] == CmdConstant.CMD_GET_FOLLOWERS:
        # followers doesn't have any arguments.
        pass
    elif command_with_args[0] == CmdConstant.CMD_GET_FOLLOWINGS:
        # followings doesn't have any arguments.
        pass
    elif command_with_args[0] == CmdConstant.CMD_TIMELINE:
        # timeline has either zero or one argument.
        max_cnt_tweets = -1
        if len(splited_raw_command) >= 2:
            max_cnt_tweets = int(splited_raw_command[1])

        arg_dict = {'max_cnt_tweets': max_cnt_tweets}
    elif command_with_args[0] == CmdConstant.CMD_GET_USER_TWEETS:
        # tweetsby has either zero or one or two arguments.
        username = None
        if len(splited_raw_command) >= 2:
            username = splited_raw_command[1]
            
        max_cnt_tweets = -1
        if len(splited_raw_command) >= 3:
            max_cnt_tweets = splited_raw_command[2]
            
        arg_dict = {'username': username, 'max_cnt_tweets': max_cnt_tweets}
    elif command_with_args[0] == CmdConstant.CMD_EXIT or command_with_args[0] == CmdConstant.CMD_QUIT:
        # exit or quit doesn't have any arguments.
        pass
    else:
        pass

    command_with_args.append(arg_dict)

    return command_with_args


def print_tweets(tweets):
    """Print a list of tweets one by one separated by "="s.
    
    Parameters
    ----------
    tweets: list(dict)
        A list of tweets. Each tweet is a dict containing the username of the tweet's author, the post time, 
        and the tweet body.
    """
    print('=' * 60)
    for index, tweet in enumerate(tweets):
        print('-' * 60)
        print('Tweet {}:'.format(index))
        print('Username:', tweet[PytwisConstant.USERNAME_KEY])
        print('Time:', datetime.datetime.fromtimestamp(int(tweet[PytwisConstant.TWEET_UNIXTIME_KEY])).strftime('%Y-%m-%d %H:%M:%S'))
        print('Body:\n\t', tweet[PytwisConstant.TWEET_BODY_KEY])
        print('-' * 60)
    print('=' * 60)


def pytwis_command_processor(twis, auth_secret, command_with_args):
    """Process the parsed command.
    
    Parameters
    ----------
    twis: Pytwis
        A Pytwis instance which interacts with the Redis database of the Twitter toy clone.
    auth_secret: str
        The authentication secret of a logged-in user.
    command_with_args:
        The parsed command output by pytwis_command_parser().
    """
    command = command_with_args[0]
    args = command_with_args[1]

    if command == CmdConstant.CMD_REGISTER:
        succeeded, result = twis.register(args['username'], args['password'])
        if succeeded:
            print('Registered {}'.format(args['username']))
        else:
            print("Couldn't register {} with error = {}".format(args['username'], result[PytwisConstant.ERROR_KEY]))
    elif command == 'login':
        succeeded, result = twis.login(args['username'], args['password'])
        if succeeded:
            auth_secret[0] = result[PytwisConstant.AUTH_KEY]
            print('Logged into username {}'.format(args['username']))
        else:
            print("Couldn't log into username {} with error = {}".format(args['username'], result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_LOGOUT:
        succeeded, result = twis.logout(auth_secret[0])
        if succeeded:
            auth_secret[0] = result[PytwisConstant.AUTH_KEY]
            print('Logged out of username {}'.format(result[PytwisConstant.USERNAME_KEY]))
        else:
            print("Couldn't log out with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_CHANGE_PASSWORD:
        succeeded, result = twis.change_password(auth_secret[0], args['old_password'], args['new_password'])
        if succeeded:
            auth_secret[0] = result[PytwisConstant.AUTH_KEY]
            print('Changed the password')
        else:
            print("Couldn't change the password with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_GET_USER_PROFILE:
        succeeded, result = twis.get_user_profile(auth_secret[0])
        if succeeded:
            print('Got the user profile')
            print('=' * 20)
            for key, value in result.items():
                print('{}: {}'.format(key, value))
            print('=' * 20)
        else:
            print("Couldn't get the user profile with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_POST:
        succeeded, result = twis.post_tweet(auth_secret[0], args['tweet'])
        if succeeded:
            print('Posted the tweet')
        else:
            print("Couldn't post the tweet with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_FOLLOW:
        succeeded, result = twis.follow(auth_secret[0], args['followee'])
        if succeeded:
            print('Followed username {}'.format(args['followee']))
        else:
            print("Couldn't follow the username {} with error = {}".format(args['followee'], result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_UNFOLLOW:
        succeeded, result = twis.unfollow(auth_secret[0], args['followee'])
        if succeeded:
            print('Unfollowed username {}'.format(args['followee']))
        else:
            print("Couldn't unfollow the username {} with error = {}".format(args['followee'], result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_GET_FOLLOWERS:
        succeeded, result = twis.get_followers(auth_secret[0])
        if succeeded:
            print('Got the list of {} followers'.format(len(result[PytwisConstant.FOLLOWER_LIST_KEY])))
            print('=' * 20)
            for follower in result[PytwisConstant.FOLLOWER_LIST_KEY]:
                print('\t' + follower)
            print('=' * 20)
        else:
            print("Couldn't get the follower list with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_GET_FOLLOWINGS:
        succeeded, result = twis.get_following(auth_secret[0])
        if succeeded:
            print('Got the list of {} followings'.format(len(result[PytwisConstant.FOLLOWING_LIST_KEY])))
            print('=' * 60)
            for following in result[PytwisConstant.FOLLOWING_LIST_KEY]:
                print('\t' + following)
            print('=' * 60)
        else:
            print("Couldn't get the following list with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_TIMELINE:
        succeeded, result = twis.get_timeline(auth_secret[0], args['max_cnt_tweets'])
        if succeeded:
            if auth_secret[0] != '':
                print('Got {} tweets in the user timeline'.format(len(result[PytwisConstant.TWEETS_KEY])))
            else:
                print('Got {} tweets in the general timeline'.format(len(result[PytwisConstant.TWEETS_KEY])))
            print_tweets(result[PytwisConstant.TWEETS_KEY])
        else:
            if auth_secret[0] != '':
                print("Couldn't get the user timeline with error = {}".format(result[PytwisConstant.ERROR_KEY]))
            else:
                print("Couldn't get the general timeline with error = {}".format(result[PytwisConstant.ERROR_KEY]))
    elif command == CmdConstant.CMD_GET_USER_TWEETS:
        # Get the username of the currently logged-in user if no username is given.
        if args['username'] is None:
            succeeded, result = twis.get_user_profile(auth_secret[0])
            if succeeded:
                args['username'] = result[PytwisConstant.USERNAME_KEY]
                print('No username is given, so use the currently logged-in user {}'.format(args['username']))
            else:
                print("Couldn't get the username of the currently logged-in user with error = {}".format(result[PytwisConstant.ERROR_KEY]))
                return
                
        succeeded, result = twis.get_user_tweets(auth_secret[0], args['username'], args['max_cnt_tweets'])
        if succeeded:
            print('Got {} tweets posted by {}'.format(len(result[PytwisConstant.TWEETS_KEY]), args['username']))
            print_tweets(result[PytwisConstant.TWEETS_KEY])
        else:
            print("Couldn't get the tweets posted by {} with error = {}".format(args['username'], result[PytwisConstant.ERROR_KEY]))
    else:
        pass


def pytwis_cli():
    """The main routine of this command-line tool."""
    epilog = '''After launching `pytwis_clt.py`, you will be able to use the following commands:

    * Register a new user:

        127.0.0.1:6379> register {username} {password}
    
    * Log into a user:  
    
        127.0.0.1:6379> login {username} {password} 
    
    * Log out of a user:
    
        127.0.0.1:6379> logout
    
    * Change the password:
    
        127.0.0.1:6379> changepwd {old_password} {new_password} {confirmed_new_password}
        
    * Get the profile of the current user:
    
        127.0.0.1:6379> userprofile
    
    * Post a tweet:
    
        127.0.0.1:6379> post {tweet}
    
    * Follow a user:
    
        127.0.0.1:6379> follow {followee_username}
    
    * Unfollow a user:
    
        127.0.0.1:6379> unfollow {followee_username}
    
    * Get the follower list:
    
        127.0.0.1:6379> followers
    
    * Get the following list:
    
        127.0.0.1:6379> followings
    
    * Get the timeline:
    
        127.0.0.1:6379> timeline
        127.0.0.1:6379> timeline {max_tweet_count}
        
    Note that if a user is logged in, `timeline` will return the user timeline; 
    otherwise `timeline` will return the general timeline.
    
    * Get the tweets posted by a user:
    
        127.0.0.1:6379> tweetsby 
        127.0.0.1:6379> tweetsby {username}
        127.0.0.1:6379> tweetsby {username} {max_tweet_count}
        
    Note that if no username is given, `tweetsby` will return the tweets posted 
    by the currently logged-in user.
    
    * Exit the program:
   
        127.0.0.1:6379> exit
        127.0.0.1:6379> quit
    '''
    # Note that we set the conflict handler of ArgumentParser to 'resolve' because we reuse the short help 
    # option '-h' for the host name.
    parser = argparse.ArgumentParser(conflict_handler="resolve", 
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=\
                                     'Connect to the Redis database of a Twitter clone and '
                                     'then run commands to access and update the database.',
                                     epilog=epilog)
    # TODO: Add epilog for the help information about online commands after connecting to the Twitter clone.
    parser.add_argument('-h', '--hostname', nargs='?', default='127.0.0.1',
                        help='''the Redis server hostname. If the option is not specified, will be defaulted to 127.0.0.1. 
                             If the option is specified but no value is given after the option, then the help information 
                             is displayed instead.
                             ''')
    parser.add_argument('-p', '--port', default=6379,
                        help='the Redis server port. If the option is not specified, will be defaulted to 6379.')
    parser.add_argument('-s', '--socket', default='',
                        help='''the Redis server socket (usually /tmp/redis.sock). If it is given, it will override hostname 
                             and port. Make sure that the unixsocket parameter is defined in your redis.conf file. It’s 
                             commented out by default.
                             ''')
    parser.add_argument('-n', '--db', default=0,
                        help='the Redis server database. If the option is not specified, will be defaulted to 0.')
    parser.add_argument('-a', '--password', default='',
                        help='the Redis server password. If the option not specified, will be defaulted to an empty string.')

    args = parser.parse_args()

    # If no value is given after the option '-h', then the help information is displayed.
    if args.hostname is None:
        parser.print_help()
        return 0

    if len(args.socket) > 0:
        print('The input Redis server socket is {}'.format(args.socket))
        prompt = args.socket
    else:
        print('The input Redis server hostname is {}.'.format(args.hostname))
        print('The input Redis server port is {}.'.format(args.port))
        prompt = '{}:{}'.format(args.hostname, args.port)
    print('The input Redis server database is {}.'.format(args.db))
    if args.password != '':
        print('The input Redis server password is "{}".'.format(args.password))
    else:
        print('The input Redis server password is empty.')

    try:
        if len(args.socket) > 0:
            twis = Pytwis(socket=args.socket, db=args.db, password=args.password)
        else:
            twis = Pytwis(hostname=args.hostname, port=args.port, db=args.db, password=args.password)
    except ValueError as e:
        print('Failed to connect to the Redis server: {}'.format(str(e)),
              file=sys.stderr)
        return -1

    auth_secret = ['']
    while True:
        try: 
            
            command_with_args = pytwis_command_parser(
                input('Please enter a command '
                      '(register, login, logout, changepwd, userprofile, post, '
                      'follow, unfollow, followers, followings, timeline, tweetsby):\n{}> '\
                      .format(prompt)))
            if command_with_args[0] == CmdConstant.CMD_EXIT \
                or command_with_args[0] == CmdConstant.CMD_QUIT:
                # Log out of the current user before exiting.
                if len(auth_secret[0]) > 0:
                    pytwis_command_processor(twis, auth_secret, [CmdConstant.CMD_LOGOUT, {}])
                print('pytwis is exiting.')
                return 0;

        except ValueError as e:
            print('Invalid pytwis command: {}'.format(str(e)),
                  file=sys.stderr)
            continue

        pytwis_command_processor(twis, auth_secret, command_with_args)


if __name__ == "__main__":
    pytwis_cli()
