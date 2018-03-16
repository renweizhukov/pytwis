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

    127.0.0.1:6379> changepassword {old_password} {new_password} {confirmed_new_password}

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

* Exit the program:

.. code:: bash

    127.0.0.1:6379> exit
    127.0.0.1:6379> quit

"""

import argparse
import datetime
import parse
import sys

from pytwis import Pytwis


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

    if (parsed_command[0] == 'register'):
        if (arg_count < 2):
            raise ValueError('register {username} {password}')
    elif (parsed_command[0] == 'login'):
        if (arg_count < 2):
            raise ValueError('login {username} {password}')
    elif (parsed_command[0] == 'logout'):
        pass
    elif (parsed_command[0] == 'changepassword'):
        if (arg_count < 3):
            raise ValueError('changepassword {old_password} {new_password} {confirmed_new_password}')
    elif (parsed_command[0] == 'post'):
        if (arg_count < 1):
            raise ValueError('post {tweet}')
    elif (parsed_command[0] == 'follow'):
        if (arg_count < 1):
            raise ValueError('follow {followee_username}')
    elif (parsed_command[0] == 'unfollow'):
        if (arg_count < 1):
            raise ValueError('unfollow {followee_username}')
    elif (parsed_command[0] == 'followers'):
        pass
    elif (parsed_command[0] == 'followings'):
        pass
    elif (parsed_command[0] == 'timeline'):
        if (arg_count > 2):
            raise ValueError('timeline {max_tweet count} or timeline')
    elif (parsed_command[0] == 'exit') or (parsed_command[0] == 'quit'):
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

    if command_with_args[0] == 'register':
        # register must have two arguments: username and password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('register has incorrect arguments')
        elif ' ' in arg_dict['password']:
            raise ValueError("password can't contain spaces")

        print('register: username = {}, password = {}'.format(arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'login':
        # login must have two arguments: username and password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('login has incorrect arguments')

        print('login: username = {}, password = {}'.format(arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'logout':
        # logout doesn't have any arguments.
        pass
    elif command_with_args[0] == 'changepassword':
        # changepassword must have three arguments: old_password, new_password, and confirmed_new_password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{old_password} {new_password} {confirmed_new_password}', args)
        if arg_dict is None:
            raise ValueError('changepassword has incorrect arguments')
        elif arg_dict['new_password'] != arg_dict['confirmed_new_password']:
            raise ValueError('The confirmed new password is different from the new password')
        elif arg_dict['new_password'] == arg_dict['old_password']:
            raise ValueError('The new password is the same as the old password')

        print('changepassword: old = {}, new = {}'.format(arg_dict['old_password'], arg_dict['new_password']))
    elif command_with_args[0] == 'post':
        # post must have one argument: tweet
        arg_dict = {'tweet': splited_raw_command[1]}
    elif command_with_args[0] == 'follow':
        # follow must have one argument: followee.
        arg_dict = {'followee': splited_raw_command[1]}
    elif command_with_args[0] == 'unfollow':
        # unfollow must have one argument: followee.
        arg_dict = {'followee': splited_raw_command[1]}
    elif command_with_args[0] == 'followers':
        # followers doesn't have any arguments.
        pass
    elif command_with_args[0] == 'followings':
        # followings doesn't have any arguments.
        pass
    elif command_with_args[0] == 'timeline':
        # timeline has either zero or one argument.
        max_cnt_tweets = -1
        if len(splited_raw_command) >= 2:
            max_cnt_tweets = int(splited_raw_command[1])

        arg_dict = {'max_cnt_tweets': max_cnt_tweets}
    elif command_with_args[0] == 'exit' or command_with_args[0] == 'quit':
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
        print('Username:', tweet['username'])
        print('Time:', datetime.datetime.fromtimestamp(int(tweet['unix_time'])).strftime('%Y-%m-%d %H:%M:%S'))
        print('Body:\n\t', tweet['body'])
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

    if command == 'register':
        succeeded, result = twis.register(args['username'], args['password'])
        if succeeded:
            print('Succeeded in registering {}'.format(args['username']))
        else:
            print('Failed to register {} with error = {}'.format(args['username'], result['error']))
    elif command == 'login':
        succeeded, result = twis.login(args['username'], args['password'])
        if succeeded:
            auth_secret[0] = result['auth']
            print('Succeeded in logging into username {}'.format(args['username']))
        else:
            print("Couldn't log into username {} with error = {}".format(args['username'], result['error']))
    elif command == 'logout':
        succeeded, result = twis.logout(auth_secret[0])
        if succeeded:
            auth_secret[0] = result['auth']
            print('Logged out of username {}'.format(result['username']))
        else:
            print("Couldn't log out with error = {}".format(result['error']))
    elif command == 'changepassword':
        succeeded, result = twis.change_password(auth_secret[0], args['old_password'], args['new_password'])
        if succeeded:
            auth_secret[0] = result['auth']
            print('Succeeded in changing the password')
        else:
            print("Couldn't change the password with error = {}".format(result['error']))
    elif command == 'post':
        succeeded, result = twis.post_tweet(auth_secret[0], args['tweet'])
        if succeeded:
            print('Succeeded in posting the tweet')
        else:
            print("Couldn't post the tweet with error = {}".format(result['error']))
    elif command == 'follow':
        succeeded, result = twis.follow(auth_secret[0], args['followee'])
        if succeeded:
            print('Succeeded in following username {}'.format(args['followee']))
        else:
            print("Couldn't follow the username {} with error = {}".format(args['followee'], result['error']))
    elif command == 'unfollow':
        succeeded, result = twis.unfollow(auth_secret[0], args['followee'])
        if succeeded:
            print('Succeeded in unfollowing username {}'.format(args['followee']))
        else:
            print("Couldn't unfollow the username {} with error = {}".format(args['followee'], result['error']))
    elif command == 'followers':
        succeeded, result = twis.get_followers(auth_secret[0])
        if succeeded:
            print('Succeeded in get the list of {} followers'.format(len(result['follower_list'])))
            print('=' * 20)
            for follower in result['follower_list']:
                print('\t' + follower)
            print('=' * 20)
        else:
            print("Couldn't get the follower list with error = {}".format(result['error']))
    elif command == 'followings':
        succeeded, result = twis.get_following(auth_secret[0])
        if succeeded:
            print('Succeeded in get the list of {} followings'.format(len(result['following_list'])))
            print('=' * 60)
            for following in result['following_list']:
                print('\t' + following)
            print('=' * 60)
        else:
            print("Couldn't get the following list with error = {}".format(result['error']))
    elif command == 'timeline':
        succeeded, result = twis.get_timeline(auth_secret[0], args['max_cnt_tweets'])
        if succeeded:
            if auth_secret[0] != '':
                print('Succeeded in get {} tweets in the user timeline'.format(len(result['tweets'])))
            else:
                print('Succeeded in get {} tweets in the general timeline'.format(len(result['tweets'])))
            print_tweets(result['tweets'])
        else:
            if auth_secret[0] != '':
                print("Couldn't get the user timeline with error = {}".format(result['error']))
            else:
                print("Couldn't get the general timeline with error = {}".format(result['error']))
    else:
        pass


def pytwis_cli():
    """The main routine of this command-line tool."""
    # Note that we set the conflict handler of ArgumentParser to 'resolve' because we reuse the short help 
    # option '-h' for the host name.
    parser = argparse.ArgumentParser(conflict_handler="resolve", description=\
                                         'Connect to the Redis database of a Twitter clone and '
                                         'then run commands to access and update the database.')
    # TODO: Add epilog for the help information about online commands after connecting to the Twitter clone.
    parser.add_argument('-h', '--hostname', nargs='?', default='127.0.0.1',
                        help='''the Redis server hostname. If the option is not specified, will be defaulted to 127.0.0.1. 
                             If the option is specified but no value is given after the option, then the help information 
                             is displayed instead.
                             ''')
    parser.add_argument('-p', '--port', default=6379,
                        help='the Redis server port. If the option is not specified, will be defaulted to 6379.')
    parser.add_argument('-n', '--db', default=0,
                        help='the Redis server database. If the option is not specified, will be defaulted to 0.')
    parser.add_argument('-a', '--password', default='',
                        help='the Redis server password. If the option not specified, will be defaulted to an empty string.')

    args = parser.parse_args()

    # If no value is given after the option '-h', then the help information is displayed.
    if args.hostname is None:
        parser.print_help()
        return 0

    print('The input Redis server hostname is {}.'.format(args.hostname))
    print('The input Redis server port is {}.'.format(args.port))
    print('The input Redis server database is {}.'.format(args.db))
    if args.password != '':
        print('The input Redis server password is "{}".'.format(args.password))
    else:
        print('The input Redis server password is empty.')

    try:
        twis = Pytwis(args.hostname, args.port, args.db, args.password)
    except ValueError as e:
        print('Failed to connect to the Redis server: {}'.format(str(e)),
              file=sys.stderr)
        return -1

    auth_secret = ['']
    while True:
        try:
            command_with_args = pytwis_command_parser(
                input('Please enter a command '
                      '(register, login, logout, changepassword, post, '
                      'follow, unfollow, followers, followings, timeline):\n{}:{}> ' \
                      .format(args.hostname, args.port)))
            if command_with_args[0] == "exit" or command_with_args[0] == 'quit':
                # Log out of the current user before exiting.
                if len(auth_secret[0]) > 0:
                    pytwis_command_processor(twis, auth_secret, ['logout', {}])
                print('pytwis is exiting.')
                return 0;

        except ValueError as e:
            print('Invalid pytwis command: {}'.format(str(e)),
                  file=sys.stderr)
            continue

        pytwis_command_processor(twis, auth_secret, command_with_args)


if __name__ == "__main__":
    pytwis_cli()
