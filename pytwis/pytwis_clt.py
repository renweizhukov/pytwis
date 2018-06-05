#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A command-line tool which uses `pytwis` to interact with the Redis database of
a Twitter toy clone.

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
import sys
import parse

if __package__:
    # If this module is imported as part of the pytwis package, then use
    # the relative import.
    from . import pytwis_constants
    from . import pytwis_clt_constants
    from . import pytwis
else:
    # If this module is executed locally as a script, then don't use
    # the relative import.
    import pytwis_constants      # pylint: disable=import-error
    import pytwis_clt_constants  # pylint: disable=import-error
    import pytwis


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

    if not parsed_command:
        return

    if parsed_command[0] == pytwis_clt_constants.CMD_REGISTER:
        if arg_count < 2:
            raise ValueError('{cmd} {{{arg1}}} {{{arg2}}}'.\
                             format(cmd=pytwis_clt_constants.CMD_REGISTER,
                                    arg1=pytwis_clt_constants.ARG_USERNAME,
                                    arg2=pytwis_clt_constants.ARG_PASSWORD))
    elif parsed_command[0] == pytwis_clt_constants.CMD_LOGIN:
        if arg_count < 2:
            raise ValueError('{cmd} {{{arg1}}} {{{arg2}}}'.\
                             format(cmd=pytwis_clt_constants.CMD_LOGIN,
                                    arg1=pytwis_clt_constants.ARG_USERNAME,
                                    arg2=pytwis_clt_constants.ARG_PASSWORD))
    elif parsed_command[0] == pytwis_clt_constants.CMD_LOGOUT:
        pass
    elif parsed_command[0] == pytwis_clt_constants.CMD_CHANGE_PASSWORD:
        if arg_count < 3:
            raise ValueError('{cmd} {{{arg1}}} {{{arg2}}} {{{arg3}}}'.\
                             format(cmd=pytwis_clt_constants.CMD_CHANGE_PASSWORD,
                                    arg1=pytwis_clt_constants.ARG_OLD_PASSWORD,
                                    arg2=pytwis_clt_constants.ARG_NEW_PASSWORD,
                                    arg3=pytwis_clt_constants.ARG_CONFIRMED_NEW_PASSWORD))
    elif parsed_command[0] == pytwis_clt_constants.CMD_GET_USER_PROFILE:
        pass
    elif parsed_command[0] == pytwis_clt_constants.CMD_POST:
        if arg_count < 1:
            raise ValueError('{cmd} {{{arg}}}'.format(cmd=pytwis_clt_constants.CMD_POST,
                                                      arg=pytwis_clt_constants.ARG_TWEET))
    elif parsed_command[0] == pytwis_clt_constants.CMD_FOLLOW:
        if arg_count < 1:
            raise ValueError('{cmd} {{{arg}}}'.format(cmd=pytwis_clt_constants.CMD_FOLLOW,
                                                      arg=pytwis_clt_constants.ARG_FOLLOWEE))
    elif parsed_command[0] == pytwis_clt_constants.CMD_UNFOLLOW:
        if arg_count < 1:
            raise ValueError('{cmd} {{{arg}}}'.format(cmd=pytwis_clt_constants.CMD_UNFOLLOW,
                                                      arg=pytwis_clt_constants.ARG_FOLLOWEE))
    elif parsed_command[0] == pytwis_clt_constants.CMD_GET_FOLLOWERS:
        pass
    elif parsed_command[0] == pytwis_clt_constants.CMD_GET_FOLLOWINGS:
        pass
    elif parsed_command[0] == pytwis_clt_constants.CMD_TIMELINE:
        if arg_count > 1:
            raise ValueError('{cmd} {{{arg}}} or {cmd}'.\
                             format(cmd=pytwis_clt_constants.CMD_TIMELINE,
                                    arg=pytwis_clt_constants.ARG_MAX_TWEETS))
    elif parsed_command[0] == pytwis_clt_constants.CMD_GET_USER_TWEETS:
        if arg_count > 2:
            raise ValueError('{cmd} {{{arg1}}} {{{arg2}}} or {cmd} {{{arg1}}} or {cmd}'.\
                             format(cmd=pytwis_clt_constants.CMD_GET_USER_TWEETS,
                                    arg1=pytwis_clt_constants.ARG_USERNAME,
                                    arg2=pytwis_clt_constants.ARG_MAX_TWEETS))
    elif (parsed_command[0] == pytwis_clt_constants.CMD_EXIT) or\
         (parsed_command[0] == pytwis_clt_constants.CMD_QUIT):
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
    arg_dict: dict(str, str or int)
        The parsed command output.
        {'command':'register', 'username': <username>, 'password': <password>} for `register`.
    Raises
    ------
    ValueError
        If the raw command can't be parsed correctly, e.g., it has an incorrect number of
        arguments or incorrect arguments.
    """
    validate_command(raw_command)

    # Some command (e.g., logout) may not have arguments.
    # Separate the command from its arguments.
    splited_raw_command = raw_command.split(' ', 1)

    arg_dict = {}

    if splited_raw_command[0] == pytwis_clt_constants.CMD_REGISTER:
        # register must have two arguments: username and password.
        args = splited_raw_command[1]

        arg_dict = parse.parse('{{{arg1}}} {{{arg2}}}'.\
                               format(arg1=pytwis_clt_constants.ARG_USERNAME,
                                      arg2=pytwis_clt_constants.ARG_PASSWORD),
                               args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.format(pytwis_clt_constants.CMD_REGISTER))
        elif ' ' in arg_dict[pytwis_clt_constants.ARG_PASSWORD]:
            raise ValueError("password can't contain spaces")

        print('{}: username = {}, password = {}'.\
              format(pytwis_clt_constants.CMD_REGISTER,
                     arg_dict[pytwis_clt_constants.ARG_USERNAME],
                     arg_dict[pytwis_clt_constants.ARG_PASSWORD]))
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_LOGIN:
        # login must have two arguments: username and password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{{{arg1}}} {{{arg2}}}'.\
                               format(arg1=pytwis_clt_constants.ARG_USERNAME,
                                      arg2=pytwis_clt_constants.ARG_PASSWORD),
                               args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.format(pytwis_clt_constants.CMD_LOGIN))

        print('{}: username = {}, password = {}'.\
              format(pytwis_clt_constants.CMD_LOGIN,
                     arg_dict[pytwis_clt_constants.ARG_USERNAME],
                     arg_dict[pytwis_clt_constants.ARG_PASSWORD]))
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_LOGOUT:
        # logout doesn't have any arguments.
        pass
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_CHANGE_PASSWORD:
        # changepwd must have three arguments: old_password, new_password, and
        # confirmed_new_password.
        args = splited_raw_command[1]
        arg_dict = parse.parse('{{{arg1}}} {{{arg2}}} {{{arg3}}}'.\
                               format(arg1=pytwis_clt_constants.ARG_OLD_PASSWORD,
                                      arg2=pytwis_clt_constants.ARG_NEW_PASSWORD,
                                      arg3=pytwis_clt_constants.ARG_CONFIRMED_NEW_PASSWORD),
                               args)
        if arg_dict is None:
            raise ValueError('{} has incorrect arguments'.\
                             format(pytwis_clt_constants.CMD_CHANGE_PASSWORD))
        elif arg_dict[pytwis_clt_constants.ARG_NEW_PASSWORD] !=\
            arg_dict[pytwis_clt_constants.ARG_CONFIRMED_NEW_PASSWORD]:
            raise ValueError('The confirmed new password is different from the new password')
        elif arg_dict[pytwis_clt_constants.ARG_NEW_PASSWORD] ==\
            arg_dict[pytwis_clt_constants.ARG_OLD_PASSWORD]:
            raise ValueError('The new password is the same as the old password')

        print('{}: old = {}, new = {}'.format(pytwis_clt_constants.CMD_CHANGE_PASSWORD,
                                              arg_dict[pytwis_clt_constants.ARG_OLD_PASSWORD],
                                              arg_dict[pytwis_clt_constants.ARG_NEW_PASSWORD]))
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_GET_USER_PROFILE:
        # userprofile doesn't have any arguments.
        pass
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_POST:
        # post must have one argument: tweet
        arg_dict = {pytwis_clt_constants.ARG_TWEET: splited_raw_command[1]}
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_FOLLOW:
        # follow must have one argument: followee.
        arg_dict = {pytwis_clt_constants.ARG_FOLLOWEE: splited_raw_command[1]}
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_UNFOLLOW:
        # unfollow must have one argument: followee.
        arg_dict = {pytwis_clt_constants.ARG_FOLLOWEE: splited_raw_command[1]}
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_GET_FOLLOWERS:
        # followers doesn't have any arguments.
        pass
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_GET_FOLLOWINGS:
        # followings doesn't have any arguments.
        pass
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_TIMELINE:
        # timeline has either zero or one argument.
        max_cnt_tweets = -1
        if len(splited_raw_command) >= 2:
            max_cnt_tweets = int(splited_raw_command[1])

        arg_dict = {pytwis_clt_constants.ARG_MAX_TWEETS: max_cnt_tweets}
    elif splited_raw_command[0] == pytwis_clt_constants.CMD_GET_USER_TWEETS:
        # tweetsby has either zero or one or two arguments.
        arg_dict = {pytwis_clt_constants.ARG_USERNAME: None,
                    pytwis_clt_constants.ARG_MAX_TWEETS: -1}

        if len(splited_raw_command) >= 2:
            # tweetsby has either one or two arguments.
            args = splited_raw_command[1]
            arg_dict = parse.parse('{{{arg1}}} {{{arg2}:d}}'.\
                                   format(arg1=pytwis_clt_constants.ARG_USERNAME,
                                          arg2=pytwis_clt_constants.ARG_MAX_TWEETS),
                                   args)
            if arg_dict is None:
                # tweetsby has only one argument.
                arg_dict = {pytwis_clt_constants.ARG_USERNAME: args}
                arg_dict[pytwis_clt_constants.ARG_MAX_TWEETS] = -1
    elif (splited_raw_command[0] == pytwis_clt_constants.CMD_EXIT) or\
        (splited_raw_command[0] == pytwis_clt_constants.CMD_QUIT):
        # exit or quit doesn't have any arguments.
        pass
    else:
        pass

    if isinstance(arg_dict, parse.Result):
        arg_dict = arg_dict.named
    arg_dict[pytwis_clt_constants.ARG_COMMAND] = splited_raw_command[0]

    return arg_dict


def print_tweets(tweets):
    """Print a list of tweets one by one separated by "="s.

    Parameters
    ----------
    tweets: list(dict)
        A list of tweets. Each tweet is a dict containing the username of the tweet's author,
        the post time, and the tweet body.
    """
    print('=' * 60)
    for index, tweet in enumerate(tweets):
        print('-' * 60)
        print('Tweet {}:'.format(index))
        print('Username:', tweet[pytwis_constants.USERNAME_KEY])
        print('Time:',
              datetime.datetime.fromtimestamp(int(tweet[pytwis_constants.TWEET_UNIXTIME_KEY])).\
              strftime('%Y-%m-%d %H:%M:%S'))
        print('Body:\n\t', tweet[pytwis_constants.TWEET_BODY_KEY])
        print('-' * 60)
    print('=' * 60)


def pytwis_command_processor(twis, auth_secret, args):
    """Process the parsed command.

    Parameters
    ----------
    twis: Pytwis
        A Pytwis instance which interacts with the Redis database of the Twitter toy clone.
    auth_secret: str
        The authentication secret of a logged-in user.
    args:
        The parsed command output by pytwis_command_parser().
    """
    command = args[pytwis_clt_constants.ARG_COMMAND]

    if command == pytwis_clt_constants.CMD_REGISTER:
        succeeded, result = twis.register(args[pytwis_clt_constants.ARG_USERNAME],
                                          args[pytwis_clt_constants.ARG_PASSWORD])
        if succeeded:
            print('Registered {}'.format(args[pytwis_clt_constants.ARG_USERNAME]))
        else:
            print("Couldn't register {} with error = {}".\
                  format(args[pytwis_clt_constants.ARG_USERNAME],
                         result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_LOGIN:
        succeeded, result = twis.login(args[pytwis_clt_constants.ARG_USERNAME],
                                       args[pytwis_clt_constants.ARG_PASSWORD])
        if succeeded:
            auth_secret[0] = result[pytwis_constants.AUTH_KEY]
            print('Logged into username {}'.format(args[pytwis_clt_constants.ARG_USERNAME]))
        else:
            print("Couldn't log into username {} with error = {}".\
                  format(args[pytwis_clt_constants.ARG_USERNAME],
                         result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_LOGOUT:
        succeeded, result = twis.logout(auth_secret[0])
        if succeeded:
            auth_secret[0] = result[pytwis_constants.AUTH_KEY]
            print('Logged out of username {}'.format(result[pytwis_constants.USERNAME_KEY]))
        else:
            print("Couldn't log out with error = {}".format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_CHANGE_PASSWORD:
        succeeded, result = twis.change_password(auth_secret[0],
                                                 args[pytwis_clt_constants.ARG_OLD_PASSWORD],
                                                 args[pytwis_clt_constants.ARG_NEW_PASSWORD])
        if succeeded:
            auth_secret[0] = result[pytwis_constants.AUTH_KEY]
            print('Changed the password')
        else:
            print("Couldn't change the password with error = {}".\
                  format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_GET_USER_PROFILE:
        succeeded, result = twis.get_user_profile(auth_secret[0])
        if succeeded:
            print('Got the user profile')
            print('=' * 20)
            for key, value in result.items():
                print('{}: {}'.format(key, value))
            print('=' * 20)
        else:
            print("Couldn't get the user profile with error = {}".\
                  format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_POST:
        succeeded, result = twis.post_tweet(auth_secret[0], args['tweet'])
        if succeeded:
            print('Posted the tweet')
        else:
            print("Couldn't post the tweet with error = {}".\
                  format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_FOLLOW:
        succeeded, result = twis.follow(auth_secret[0],
                                        args[pytwis_clt_constants.ARG_FOLLOWEE])
        if succeeded:
            print('Followed username {}'.format(args[pytwis_clt_constants.ARG_FOLLOWEE]))
        else:
            print("Couldn't follow the username {} with error = {}".\
                  format(args[pytwis_clt_constants.ARG_FOLLOWEE],
                         result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_UNFOLLOW:
        succeeded, result = twis.unfollow(auth_secret[0],
                                          args[pytwis_clt_constants.ARG_FOLLOWEE])
        if succeeded:
            print('Unfollowed username {}'.format(args[pytwis_clt_constants.ARG_FOLLOWEE]))
        else:
            print("Couldn't unfollow the username {} with error = {}".\
                  format(args[pytwis_clt_constants.ARG_FOLLOWEE],
                         result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_GET_FOLLOWERS:
        succeeded, result = twis.get_followers(auth_secret[0])
        if succeeded:
            print('Got the list of {} followers'.\
                  format(len(result[pytwis_constants.FOLLOWER_LIST_KEY])))
            print('=' * 20)
            for follower in result[pytwis_constants.FOLLOWER_LIST_KEY]:
                print('\t' + follower)
            print('=' * 20)
        else:
            print("Couldn't get the follower list with error = {}".\
                  format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_GET_FOLLOWINGS:
        succeeded, result = twis.get_following(auth_secret[0])
        if succeeded:
            print('Got the list of {} followings'.\
                  format(len(result[pytwis_constants.FOLLOWING_LIST_KEY])))
            print('=' * 60)
            for following in result[pytwis_constants.FOLLOWING_LIST_KEY]:
                print('\t' + following)
            print('=' * 60)
        else:
            print("Couldn't get the following list with error = {}".\
                  format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_TIMELINE:
        succeeded, result = twis.get_timeline(auth_secret[0],
                                              args[pytwis_clt_constants.ARG_MAX_TWEETS])
        if succeeded:
            if auth_secret[0] != '':
                print('Got {} tweets in the user timeline'.\
                      format(len(result[pytwis_constants.TWEETS_KEY])))
            else:
                print('Got {} tweets in the general timeline'.\
                      format(len(result[pytwis_constants.TWEETS_KEY])))
            print_tweets(result[pytwis_constants.TWEETS_KEY])
        else:
            if auth_secret[0] != '':
                print("Couldn't get the user timeline with error = {}".\
                      format(result[pytwis_constants.ERROR_KEY]))
            else:
                print("Couldn't get the general timeline with error = {}".\
                      format(result[pytwis_constants.ERROR_KEY]))
    elif command == pytwis_clt_constants.CMD_GET_USER_TWEETS:
        # Get the username of the currently logged-in user if no username is given.
        if args[pytwis_clt_constants.ARG_USERNAME] is None:
            succeeded, result = twis.get_user_profile(auth_secret[0])
            if succeeded:
                args[pytwis_clt_constants.ARG_USERNAME] = result[pytwis_constants.USERNAME_KEY]
                print('No username is given, so use the currently logged-in user {}'.\
                      format(args[pytwis_clt_constants.ARG_USERNAME]))
            else:
                print("Couldn't get the username of the currently logged-in user with error = {}".\
                      format(result[pytwis_constants.ERROR_KEY]))
                return

        succeeded, result = twis.get_user_tweets(auth_secret[0],
                                                 args[pytwis_clt_constants.ARG_USERNAME],
                                                 args[pytwis_clt_constants.ARG_MAX_TWEETS])
        if succeeded:
            print('Got {} tweets posted by {}'.format(len(result[pytwis_constants.TWEETS_KEY]),
                                                      args[pytwis_clt_constants.ARG_USERNAME]))
            print_tweets(result[pytwis_constants.TWEETS_KEY])
        else:
            print("Couldn't get the tweets posted by {} with error = {}".\
                  format(args[pytwis_clt_constants.ARG_USERNAME],
                         result[pytwis_constants.ERROR_KEY]))
    else:
        pass


def get_pytwis(epilog):
    """Connect to the Redis database and return the Pytwis instance.

    Parameters
    ----------
    epilog: str
        An epilog string which will be displayed by ArgumentParser.

    Returns
    -------
    pytwis: A Pytwis instance.
    prompt: str
        The prompt string which contains either the hostname and the port or the socket.
    Raises
    ------
    ValueError
        If we fail to connect to the Redis server.
    """
    # Note that we set the conflict handler of ArgumentParser to 'resolve' because we reuse
    # the short help option '-h' for the host name.
    parser = argparse.ArgumentParser(conflict_handler="resolve",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=\
                                     'Connect to the Redis database of a Twitter clone and '
                                     'then run commands to access and update the database.',
                                     epilog=epilog)
    parser.add_argument('-h', '--hostname', nargs='?', default='127.0.0.1',
                        help='''the Redis server hostname. If the option is not specified,
                             will be defaulted to 127.0.0.1. If the option is specified but
                             no value is given after the option, then the help information
                             is displayed instead.
                             ''')
    parser.add_argument('-p', '--port', default=6379,
                        help='''the Redis server port. If the option is not specified, will
                             be defaulted to 6379.
                             ''')
    parser.add_argument('-s', '--socket', default='',
                        help='''the Redis server socket (usually /tmp/redis.sock). If it is
                             given, it will override hostname and port. Make sure that the
                             unixsocket parameter is defined in your redis.conf file. It’s
                             commented out by default.
                             ''')
    parser.add_argument('-n', '--db', default=0,
                        help='''the Redis server database. If the option is not specified,
                             will be defaulted to 0.
                             ''')
    parser.add_argument('-a', '--password', default='',
                        help='''the Redis server password. If the option not specified,
                             will be defaulted to an empty string.
                             ''')

    args = parser.parse_args()

    # If no value is given after the option '-h', then the help information is displayed.
    if args.hostname is None:
        parser.print_help()
        return 0

    if args.socket:
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
        if args.socket:
            twis = pytwis.Pytwis(socket=args.socket,
                                 db=args.db,
                                 password=args.password)
        else:
            twis = pytwis.Pytwis(hostname=args.hostname,
                                 port=args.port,
                                 db=args.db,
                                 password=args.password)
        return twis, prompt

    except ValueError as excep:
        print('Failed to connect to the Redis server: {}'.format(str(excep)),
              file=sys.stderr)
        return None, None

def pytwis_clt():
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
    twis, prompt = get_pytwis(epilog)
    if twis is None:
        return -1

    auth_secret = ['']
    while True:
        try:
            arg_dict = pytwis_command_parser(
                input('Please enter a command '
                      '(register, login, logout, changepwd, userprofile, post, '
                      'follow, unfollow, followers, followings, timeline, tweetsby):\n{}> '\
                      .format(prompt)))
            if arg_dict[pytwis_clt_constants.ARG_COMMAND] == pytwis_clt_constants.CMD_EXIT \
                or arg_dict[pytwis_clt_constants.ARG_COMMAND] == pytwis_clt_constants.CMD_QUIT:
                # Log out of the current user before exiting.
                if auth_secret[0]:
                    pytwis_command_processor(twis, auth_secret,
                                             {pytwis_clt_constants.ARG_COMMAND:
                                              pytwis_clt_constants.CMD_LOGOUT})
                print('pytwis is exiting.')
                return 0

        except ValueError as excep:
            print('Invalid pytwis command: {}'.format(str(excep)),
                  file=sys.stderr)
            continue

        pytwis_command_processor(twis, auth_secret, arg_dict)


if __name__ == "__main__":
    pytwis_clt()
