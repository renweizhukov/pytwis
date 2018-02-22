#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import parse
import sys

import pytwis

def pytwis_command_parser(raw_command):
    # Separate the command from its arguments.
    splited_raw_command = raw_command.split(' ', 1)
    command_with_args = [splited_raw_command[0]]

    # Some command (e.g., logout) may not have arguments.
    arg_dict = {}
    
    if command_with_args[0] == 'register':
        # register must have two arguments: username and password.
        if len(splited_raw_command) < 2:
            raise ValueError('register has NO arguments')
            
        args = splited_raw_command[1]
        arg_dict = parse.parse('{username} {password}', args)
        if arg_dict is None:
            raise ValueError('register has incorrect arguments')
        
        print('register: username = {}, password = {}'.format(arg_dict['username'], arg_dict['password']))
    elif command_with_args[0] == 'login':
        # login must have two arguments: username and password.
        if len(splited_raw_command) < 2:
            raise ValueError('login has NO arguments')
            
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
        if len(splited_raw_command) < 2:
            raise ValueError('changepassword has NO arguments')
            
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
        if len(splited_raw_command) < 2:
            raise ValueError('post has NO arguments')
        
        arg_dict = {'tweet': splited_raw_command[1]}
    elif command_with_args[0] == 'follow':
        # follow must have one argument: followee.
        if len(splited_raw_command) < 2:
            raise ValueError('follow has NO arguments')
        
        arg_dict = {'followee': splited_raw_command[1]}
    elif command_with_args[0] == 'unfollow':
        # unfollow must have one argument: followee.
        if len(splited_raw_command) < 2:
            raise ValueError('unfollow has NO arguments')
        
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
        raise ValueError('Invalid pytwis command')
    
    command_with_args.append(arg_dict)
    
    return command_with_args

def print_tweets(tweets):
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
            auth_secret[0] = ''
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
    # TODO: Add epilog for the help information about online commands after connecting to the Twitter clone.
    parser = argparse.ArgumentParser(description=\
                                     'Connect to the Redis database of a Twitter clone and '
                                     'then run commands to access and update the database.')
    parser.add_argument('-d', '--hostname', dest='redis_hostname', default = '127.0.0.1', 
                        help='the Redis server hostname. If not specified, will be defaulted to 127.0.0.1.')
    parser.add_argument('-t', '--port', dest='redis_port', default = 6379,
                        help='the Redis server port. If not specified, will be defaulted to 6379.')
    parser.add_argument('-p', '--password', dest='redis_password', default = '',
                        help='the Redis server password. If not specified, will be defaulted to an empty string.')
    
    args = parser.parse_args()
    
    print('The input Redis server hostname is {}.'.format(args.redis_hostname))
    print('The input Redis server port is {}.'.format(args.redis_port))
    if args.redis_password != '':
        print('The input Redis server password is "{}".'.format(args.redis_password))
    else:
        print('The input Redis server password is empty.')
    
    try:
        twis = pytwis.Pytwis(args.redis_hostname, args.redis_port, args.redis_password)
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
                      'follow, unfollow, followers, followings, timeline):\n{}:{}> '\
                      .format(args.redis_hostname, args.redis_port)))
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