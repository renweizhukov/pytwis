#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A `pytwis` unittest based on the Python built-in `unittest` framework.

Note
----
This unittest does require that a Redis server is running in localhost, so 
strictly speaking, it is a little integration test.
"""
import unittest
from werkzeug.security import check_password_hash
from .context import pytwis


INCORRECT_ERROR_MSG = 'Incorrect error message'
# By default the database index ranges from 0 to 15.
TEST_DATABASE_ID = 15


class PytwisTests(unittest.TestCase):
    """Pytwis test base class which has the general setUp() and tearDown() methods."""
    
    def setUp(self):
        """Set up the register test.
        
        (1) Connect to the test database of the local Redis server.
        
        (2) Delete all the keys of the test database via `flushdb`. 
        Note that do NOT use `flushall` which will delete all the 
        keys of all the existing databases. 
        """
        try:
            self._pytwis = pytwis.Pytwis(db=TEST_DATABASE_ID)
        except ValueError as e:
            self.fail('Failed to connect to the Redis server: {}'.format(str(e)))
            
        self._pytwis._rc.flushdb()
    
    def tearDown(self):
        """Clean up after the register test is done.
        
        Delete all the keys of the test database
        """
        self._pytwis._rc.flushdb()


class PytwisRegisterTests(PytwisTests):
    """Test for the `Pytwis.register()` function."""
    
    def _register_new_and_existing_users(self):
        """Register a new user and then an existing user."""
        username = 'test1_username'
        password = 'test1_Password'
        succeeded, _ = self._pytwis.register(username, password)
        self.assertTrue(succeeded, 'Failed to register a new username')
        
        succeeded, result = self._pytwis.register(username, password)
        self.assertFalse(succeeded, 'Succeeded in registering an existing username')
        self.assertEqual(pytwis.pytwis_constants.ERROR_USERNAME_ALREADY_EXISTS.format(username), 
                         result[pytwis.pytwis_constants.ERROR_KEY],
                         INCORRECT_ERROR_MSG)
        
    def _register_same_user_at_same_time(self):
        """Register the same user in two threads almost simultaneously."""
        username = 'test2_username'
        password = 'test2_Password'
        
        from multiprocessing.pool import ThreadPool
        pool = ThreadPool(processes=1)
        
        async_result1 = pool.apply_async(self._pytwis.register, (username, password))
        async_result2 = pool.apply_async(self._pytwis.register, (username, password))
        
        succeeded1, _ = async_result1.get()
        succeeded2, _ = async_result2.get()
        
        self.assertTrue(succeeded1 != succeeded2, 
                        'One register should succeed and the other register should fail')
        
    def _register_invalid_username(self):
        """Register a new user with an invalid username."""
        username = '12345678'
        password = 'test3_Password'
        succeeded, result = self._pytwis.register(username, password)
        self.assertFalse(succeeded, 'Succeeded in registering an invalid username')
        self.assertEqual(pytwis.pytwis_constants.ERROR_INVALID_USERNAME, 
                         result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
        
    def _register_weak_password(self):
        """Register a new user with a weak password."""
        username = 'test4_username'
        password = '11111111'
        succeeded, result = self._pytwis.register(username, password)
        self.assertFalse(succeeded, 'Succeeded in registering a user with a weak password')
        self.assertEqual(pytwis.pytwis_constants.ERROR_WEAK_PASSWORD, 
                         result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
        
    def test_register(self):
        """Register test routine:
        (1) _register_new_and_existing_users
        (2) _register_same_user_at_same_time
        (3) _register_invalid_username
        (4) _register_weak_password
        """
        self._register_new_and_existing_users()
        self._register_same_user_at_same_time()
        self._register_invalid_username()
        self._register_weak_password()


class PytwisTestsWithRegisteredUsers(PytwisTests):
    """Pytwis test class which inherits from PytwisTests and register some new users in setUp()."""
    
    CNT_REGISTERED_USERS = 2
    
    def setUp(self):
        """After PytwisTests.setUp(), we register some new users to prepare for the subsequent tests."""
        PytwisTests.setUp(self)
        
        self._usernames = ['username_{}'.format(i) for i in range(self.CNT_REGISTERED_USERS)]
        self._passwords = ['Password_{}'.format(i) for i in range(self.CNT_REGISTERED_USERS)]

        for username, password in zip(self._usernames, self._passwords):
            succeeded, _ = self._pytwis.register(username, password)
            self.assertTrue(succeeded, 'Failed to register user {}'.format(username))


class PytwisLogTests(PytwisTestsWithRegisteredUsers):
    """Test for the `Pytwis.login()` and `Pytwis.logout()` functions."""
    
    def _login_with_empty_username(self):
        """Log in with an empty username."""
        succeeded, result = self._pytwis.login('', self._passwords[0])
        self.assertFalse(succeeded, 'Succeeded in logging in with an empty username')
        self.assertEqual(pytwis.pytwis_constants.ERROR_USERNAME_NOT_EXIST_FORMAT.format(''), result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
        
    def _login_with_wrong_username(self):
        """Log in with a wrong username."""
        wrong_username = self._usernames[0] + '_wrong'
        succeeded, result = self._pytwis.login(wrong_username, self._passwords[0])
        self.assertFalse(succeeded, 'Succeeded in logging in with a wrong username {}'.format(wrong_username))
        self.assertEqual(pytwis.pytwis_constants.ERROR_USERNAME_NOT_EXIST_FORMAT.format(wrong_username), result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
    
    def _login_with_correct_password(self):
        """Log into the user with correct password."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 
                        'Failed to log into user {} with the correct password {}'.\
                        format(self._usernames[0], self._passwords[0]))
        self.assertGreater(len(result[pytwis.pytwis_constants.AUTH_KEY]), 0, 'login returns an empty authentication secret')

    def _login_with_empty_password(self):
        """Log into the user with an empty password."""
        succeeded, result = self._pytwis.login(self._usernames[0], '')
        self.assertFalse(succeeded, 'Succeeded in logging into {} with an empty password'.format(self._usernames[0]))
        self.assertEqual(pytwis.pytwis_constants.ERROR_INCORRECT_PASSWORD, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _login_with_wrong_password(self):
        """Log into the user with wrong password."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0] + '_wrong')
        self.assertFalse(succeeded, 'Succeeded in logging into {} with wrong password'.format(self._usernames[0]))
        self.assertEqual(pytwis.pytwis_constants.ERROR_INCORRECT_PASSWORD, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)

    def _logout_before_login(self):
        """Log out before log in."""
        succeeded, result = self._pytwis.logout('')
        self.assertFalse(succeeded, 'Succeeded in logging out before logging in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _logout_after_login(self):
        """Log out after log in."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 
                        'Failed to log into user {} with the correct password {}'.\
                        format(self._usernames[0], self._passwords[0]))
        auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        
        succeeded, _ = self._pytwis.logout(auth_secret)
        self.assertTrue(succeeded, 'Failed to log out user {}'.format(self._usernames[0]))
    
    def _login_logout_login_new_auth_secret(self):
        """Log in, log out, and log in again. 
        Two logins should return different authentication secrets. 
        """
        _, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        auth_secret1 = result[pytwis.pytwis_constants.AUTH_KEY]
        
        self._pytwis.logout(auth_secret1)
        
        _, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        auth_secret2 = result[pytwis.pytwis_constants.AUTH_KEY]
        self.assertNotEqual(auth_secret1, auth_secret2, 
                            'Two logins return the same authentication secret')
    
    def test_log(self):
        """Login/Logout test routines:
        (1) _login_with_empty_username
        (2) _login_with_wrong_username
        (3) _login_with_correct_password
        (4) _login_with_empty_password
        (5) _login_with_wrong_password
        (6) _logout_before_login
        (7) _logout_after_login
        (8) _login_logout_login_new_auth_secret
        """
        self._login_with_empty_username()
        self._login_with_wrong_username()
        self._login_with_correct_password()
        self._login_with_empty_password()
        self._login_with_wrong_password()
        self._logout_before_login()
        self._logout_after_login()
        self._login_logout_login_new_auth_secret()


class PytwisChangePasswordTests(PytwisTestsWithRegisteredUsers):
    """Test for the `Pytwis.change_password()` function."""
    
    def _change_password_before_login(self):
        """Change the password before logging in."""
        succeeded, result = self._pytwis.change_password('', 'old_password', 'new_password')
        self.assertFalse(succeeded, 'Succeeded in changing the password before logging in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
    
    def _change_password_with_wrong_old_password(self):
        """Change the password with the wrong old password."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 'Failed to log in.')
        auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        
        succeeded, result = self._pytwis.change_password(auth_secret, self._passwords[0] + '_wrong', '')
        self.assertFalse(succeeded, 'Succeeded in changing the password with incorrect old password')
        self.assertEqual(pytwis.pytwis_constants.ERROR_INCORRECT_OLD_PASSWORD, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _change_password_with_same_new_password(self):
        """Change the password with the same new password."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 'Failed to log in.')
        auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        
        succeeded, result = self._pytwis.change_password(auth_secret, self._passwords[0], self._passwords[0])
        self.assertFalse(succeeded, 'Succeeded in changing the password with same new password')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NEW_PASSWORD_NO_CHANGE, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _change_password_with_weak_new_password(self):
        """Change the password with a weak new password."""
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 'Failed to log in.')
        auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        
        succeeded, result = self._pytwis.change_password(auth_secret, self._passwords[0], '12345678')
        self.assertFalse(succeeded, 'Succeeded in changing the password with a weak new password')
        self.assertEqual(pytwis.pytwis_constants.ERROR_WEAK_PASSWORD, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
    
    def _change_password_after_login_then_logout_login(self):
        """Change the password after logging in, 
        then log out and log in with the new password 
        """
        old_password = self._passwords[0]
        succeeded, result = self._pytwis.login(self._usernames[0], old_password)
        self.assertTrue(succeeded, 'Succeeded in logging in with the old password.')
        old_auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        
        new_password = self._passwords[0] + '_new'
        succeeded, result = self._pytwis.change_password(old_auth_secret, old_password, new_password)
        self.assertTrue(succeeded, 'Succeeded in changing the password.')
        new_auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        self.assertNotEqual(old_auth_secret, new_auth_secret, 
                            'The new authentication secret is the same as the old one')
        
        succeeded, _ = self._pytwis.logout(new_auth_secret)
        self.assertTrue(succeeded, 'Failed to log out')
        
        succeeded, result = self._pytwis.login(self._usernames[0], old_password)
        self.assertFalse(succeeded, 'Succeeded in logging in with the old password')
        self.assertEqual(pytwis.pytwis_constants.ERROR_INCORRECT_PASSWORD, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
        succeeded, _ = self._pytwis.login(self._usernames[0], new_password)
        self.assertTrue(succeeded, 'Failed to log in with the new password')
        
    def test_change_password(self):
        """change_password test routines:
        (1) _change_password_before_login
        (2) _change_password_with_wrong_old_password
        (3) _change_password_with_same_new_password
        (4) _change_password_with_weak_new_password
        (5) _change_password_after_login_then_logout_login
        """
        self._change_password_before_login()
        self._change_password_with_wrong_old_password()
        self._change_password_with_same_new_password()
        self._change_password_with_weak_new_password()
        self._change_password_after_login_then_logout_login()


class PytwisUserProfileTests(PytwisTestsWithRegisteredUsers):
    """Test for the `Pytwis.get_user_profile()` function."""
    
    def setUp(self):
        """Besides PytwisTestsWithRegisteredUsers.setUp(), we log into one user 
        and store his/her authentication secret for the subsequent tests.
        """
        PytwisTestsWithRegisteredUsers.setUp(self)
        
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 
                        'Failed to log into user {} with the correct password {}'.\
                        format(self._usernames[0], self._passwords[0]))
        self._auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
    
    def _get_user_profile_with_empty_auth_secret(self):
        """Try getting the user profile with an empty authentication secret."""
        succeeded, result = self._pytwis.get_user_profile('')
        self.assertFalse(succeeded, 'Succeeded in getting the user profile with an empty authentication secret')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _get_user_profile_with_incorrect_auth_secret(self):
        """Try getting the user profile with an incorrect authentication secret."""
        succeeded, result = self._pytwis.get_user_profile(self._auth_secret + '_wrong')
        self.assertFalse(succeeded, 'Succeeded in getting the user profile with an incorrect authentication secret')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
    def _get_user_profile_with_correct_auth_secret(self):
        """Get the user profile with the correct authentication secret."""
        succeeded, result = self._pytwis.get_user_profile(self._auth_secret)
        self.assertTrue(succeeded, 'Failed to get the user profile with the correct authentication secret')
        self.assertEqual(self._usernames[0], result[pytwis.pytwis_constants.USERNAME_KEY], 'Mismatched username')
        self.assertTrue(check_password_hash(result[pytwis.pytwis_constants.PASSWORD_HASH_KEY], self._passwords[0]), 'Mismatched password')
        self.assertEqual(self._auth_secret, result[pytwis.pytwis_constants.AUTH_KEY], 'Mismatched authentication secret')
        
    def test_get_user_profile(self):
        """get_user_profile test routines:
        (1) _get_user_profile_with_empty_auth_secret
        (2) _get_user_profile_with_incorrect_auth_secret
        (3) _get_user_profile_with_correct_auth_secret
        """
        self._get_user_profile_with_empty_auth_secret()
        self._get_user_profile_with_incorrect_auth_secret()
        self._get_user_profile_with_correct_auth_secret()


class PytwisTimelineTests(PytwisTestsWithRegisteredUsers):
    """Pytwis test class which inherits from PytwisTestsWithRegisteredUsers and 
    log into some users in setUp(). It also provides a couple of test routines 
    shared by the general-timeline tests and the user-timeline tests.
    """
    
    def setUp(self):
        """Besides PytwisTestsWithRegisteredUsers.setUp(), we log into one user 
        and store his/her authentication secret for the subsequent tests.
        """
        PytwisTestsWithRegisteredUsers.setUp(self)
        
        succeeded, result = self._pytwis.login(self._usernames[0], self._passwords[0])
        self.assertTrue(succeeded, 
                        'Failed to log into user {} with the correct password {}'.\
                        format(self._usernames[0], self._passwords[0]))
        self._post_auth_secret = result[pytwis.pytwis_constants.AUTH_KEY]
        self._get_auth_secret = ''
    
    def _get_empty_timeline(self):
        """Get an empty timeline."""
        succeeded, result = self._pytwis.get_timeline(self._get_auth_secret, -1)
        self.assertTrue(succeeded, 'Failed to get the empty timeline')
        self.assertEqual(0, len(result[pytwis.pytwis_constants.TWEETS_KEY]), 'Get a non-empty timeline')
        
    def _get_nonempty_timeline_all(self):
        """Get all the tweets of a nonempty timeline."""
        self._cnt_tweets = 10
        for tweet_index in range(0, self._cnt_tweets):
            succeeded, _ = self._pytwis.post_tweet(self._post_auth_secret, 'Test tweet {}'.format(tweet_index))
            self.assertTrue(succeeded, 'Failed to post the tweet {}'.format(tweet_index))
        
        # Get all the general timeline.
        succeeded, result = self._pytwis.get_timeline(self._get_auth_secret, -1)
        self.assertTrue(succeeded, 'Failed to get the non-empty timeline')
        self.assertEqual(self._cnt_tweets, len(result[pytwis.pytwis_constants.TWEETS_KEY]), 'Get an incorrect number of tweets')
        
    def _get_nonempty_timeline_fewer(self):
        """Get fewer than available tweets."""
        succeeded, result = self._pytwis.get_timeline(self._get_auth_secret, self._cnt_tweets//2)
        self.assertTrue(succeeded, 'Failed to get fewer than available tweets')
        self.assertEqual(self._cnt_tweets//2, len(result[pytwis.pytwis_constants.TWEETS_KEY]), 'Get an incorrect number of tweets')
        
    def _get_nonempty_timeline_more(self):
        """Get more than available tweets."""
        succeeded, result = self._pytwis.get_timeline(self._get_auth_secret, self._cnt_tweets*2)
        self.assertTrue(succeeded, 'Failed to get more than available tweets')
        self.assertEqual(self._cnt_tweets, len(result[pytwis.pytwis_constants.TWEETS_KEY]), 'Get an incorrect number of tweets')


class PytwisGeneralTimelineTests(PytwisTimelineTests):
    """Test for the `Pytwis.get_timeline()` and `Pytwis.post_tweet()` functions 
    for the general timeline.
    """
    
    def test_general_timeline(self):
        """get_timeline test routines for the general timeline:
        (1) _get_empty_timeline
        (2) _get_nonempty_timeline_all
        (3) _get_nonempty_timeline_fewer
        (4) _get_nonempty_timeline_more
        """
        self._get_empty_timeline()
        self._get_nonempty_timeline_all()
        self._get_nonempty_timeline_fewer()
        self._get_nonempty_timeline_more()


class PytwisUserTimelineTestsWithoutFollow(PytwisTimelineTests):
    """Test for the `Pytwis.get_timeline()` and `Pytwis.post_tweet()` functions 
    for the user timeline without followers.
    """
    
    def setUp(self):
        """Besides PytwisTimelineTests.setUp(), we select one user to get his/her timeline."""
        PytwisTimelineTests.setUp(self)
        self._get_auth_secret = self._post_auth_secret
    
    def test_user_timeline(self):
        """get_timeline test routines for the user timeline:
        (1) _get_empty_timeline
        (2) _get_nonempty_timeline_all
        (3) _get_nonempty_timeline_fewer
        (4) _get_nonempty_timeline_more
        """
        self._get_empty_timeline()
        self._get_nonempty_timeline_all()
        self._get_nonempty_timeline_fewer()
        self._get_nonempty_timeline_more()


class PytwisFollowTests(PytwisTestsWithRegisteredUsers):
    """Test for the follow-related `Pytwis` functions:
    (1) `follow()` 
    (2) `unfollow()` 
    (3) `get_followers`, 
    (4) `get_following()`
    """
    
    CNT_REGISTERED_USERS = 11
    
    def setUp(self):
        """Besides PytwisTestsWithRegisteredUsers.setUp(), we log into the users 
        and store their authentication secrets for the subsequent tests.
        """
        PytwisTestsWithRegisteredUsers.setUp(self)
        
        self._auth_secrets = []
        for user_index in range(0, self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.login(self._usernames[user_index], self._passwords[user_index])
            self.assertTrue(succeeded, 
                            'Failed to log into user {} with the correct password {}'.\
                            format(self._usernames[user_index], self._passwords[user_index]))
            self._auth_secrets.append(result[pytwis.pytwis_constants.AUTH_KEY])
    
    def _follow_unfollow_before_login(self):
        """Test for the follow-related functions before logged in."""
        succeeded, result = self._pytwis.follow('', self._usernames[0])
        self.assertFalse(succeeded, 'Succeeded in following another user before logged in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
        succeeded, result = self._pytwis.unfollow('', self._usernames[0])
        self.assertFalse(succeeded, 'Succeeded in unfollowing another user before logged in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
        succeeded, result = self._pytwis.get_followers('')
        self.assertFalse(succeeded, 'Succeeded in getting the follower list before logged in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
        
        succeeded, result = self._pytwis.get_following('')
        self.assertFalse(succeeded, 'Succeeded in getting the following list before logged in')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
    
    def _follow_unfollow_correct_username_after_login(self):
        """Test for the follow-related functions after logged in 
        with a correct username.
        """
        succeeded, _ = self._pytwis.follow(self._auth_secrets[0], self._usernames[1])
        self.assertTrue(succeeded, 'Failed to follow another user after logged in')
        
        succeeded, result = self._pytwis.get_following(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the following list after a follow')
        self.assertEqual(1, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                         'Incorrect number of followings after a follow')
        
        succeeded, result = self._pytwis.get_followers(self._auth_secrets[1])
        self.assertTrue(succeeded, 'Failed to get the follower list after a follow')
        self.assertEqual(1, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                         'Incorrect number of followers after a follow')
        
        succeeded, _ = self._pytwis.unfollow(self._auth_secrets[0], self._usernames[1])
        self.assertTrue(succeeded, 'Failed to unfollow another user after logged in')
        
        succeeded, result = self._pytwis.get_following(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the following list after an unfollow')
        self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                         'Incorrect number of followings after an unfollow')
        
        succeeded, result = self._pytwis.get_followers(self._auth_secrets[1])
        self.assertTrue(succeeded, 'Failed to get the follower list after an unfollow')
        self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                         'Incorrect number of followers after an unfollow')

    def _follow_unfollow_wrong_username_after_login(self):
        """Test `follow()` and `unfollow()` with the wrong usernames."""
        wrong_followee = self._usernames[1] + '_wrong'
        succeeded, result = self._pytwis.follow(self._auth_secrets[0], wrong_followee)
        self.assertFalse(succeeded, 'Succeeded in following a wrong username {}'.format(wrong_followee))
        self.assertEqual(pytwis.pytwis_constants.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(wrong_followee), result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
        
        succeeded, result = self._pytwis.unfollow(self._auth_secrets[0], wrong_followee)
        self.assertFalse(succeeded, 'Succeeded in unfollowing a wrong username {}'.format(wrong_followee))
        self.assertEqual(pytwis.pytwis_constants.ERROR_FOLLOWEE_NOT_EXIST_FORMAT.format(wrong_followee), result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)
    
    def _follow_yourself_after_login(self):
        """Test `follow()` with the logged-in username."""
        succeeded, result = self._pytwis.follow(self._auth_secrets[0], self._usernames[0])
        self.assertFalse(succeeded, 'Succeeded in following yourself {}'.format(self._usernames[0]))
        self.assertEqual(pytwis.pytwis_constants.ERROR_FOLLOW_YOURSELF_FORMAT.format(self._usernames[0]), result[pytwis.pytwis_constants.ERROR_KEY], 
                         INCORRECT_ERROR_MSG)

    def _one_follow_multiple(self):
        """Test the scenario where one user follows multiple users."""
        for followee_index in range(1, self.CNT_REGISTERED_USERS):
            succeeded, _ = self._pytwis.follow(self._auth_secrets[0], self._usernames[followee_index])
            self.assertTrue(succeeded, '{} failed to follow {}'.\
                            format(self._usernames[0], self._usernames[followee_index]))
            
            succeeded, result = self._pytwis.get_followers(self._auth_secrets[followee_index])
            self.assertTrue(succeeded, 'Failed to get the follower list for {}'.format(self._usernames[followee_index]))
            self.assertEqual(1, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                            'Incorrect number of followers for {}'.format(self._usernames[followee_index]))
            
        succeeded, result = self._pytwis.get_following(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the following list for {}'.format(self._usernames[0]))
        self.assertEqual(self.CNT_REGISTERED_USERS - 1, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                        'Incorrect number of followings for {}'.format(self._usernames[0]))
        
        for followee_index in range(1, self.CNT_REGISTERED_USERS):
            succeeded, _ = self._pytwis.unfollow(self._auth_secrets[0], self._usernames[followee_index])
            self.assertTrue(succeeded, '{} failed to unfollow {}'.\
                            format(self._usernames[0], self._usernames[followee_index]))
            
            succeeded, result = self._pytwis.get_followers(self._auth_secrets[followee_index])
            self.assertTrue(succeeded, 'Failed to get the follower list for {}'.format(self._usernames[followee_index]))
            self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                            'Incorrect number of followers for {}'.format(self._usernames[followee_index]))
            
        succeeded, result = self._pytwis.get_following(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the following list for {}'.format(self._usernames[0]))
        self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                        'Incorrect number of followings for {}'.format(self._usernames[0]))
        
    def _multiple_follow_one(self):
        """Test the scenario where multiple users follow one user."""
        for follower_index in range(1, self.CNT_REGISTERED_USERS):
            succeeded, _ = self._pytwis.follow(self._auth_secrets[follower_index], self._usernames[0])
            self.assertTrue(succeeded, '{} failed to follow {}'.\
                            format(self._usernames[follower_index], self._usernames[0]))
            
            succeeded, result = self._pytwis.get_following(self._auth_secrets[follower_index])
            self.assertTrue(succeeded, 'Failed to get the following list for {}'.format(self._usernames[follower_index]))
            self.assertEqual(1, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                            'Incorrect number of followings for {}'.format(self._usernames[follower_index]))
            
        succeeded, result = self._pytwis.get_followers(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the follower list for {}'.format(self._usernames[0]))
        self.assertEqual(self.CNT_REGISTERED_USERS - 1, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                        'Incorrect number of followers for {}'.format(self._usernames[0]))
        
        for follower_index in range(1, self.CNT_REGISTERED_USERS):
            succeeded, _ = self._pytwis.unfollow(self._auth_secrets[follower_index], self._usernames[0])
            self.assertTrue(succeeded, '{} failed to unfollow {}'.\
                            format(self._usernames[follower_index], self._usernames[0]))
            
            succeeded, result = self._pytwis.get_following(self._auth_secrets[follower_index])
            self.assertTrue(succeeded, 'Failed to get the following list for {}'.format(self._usernames[follower_index]))
            self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWING_LIST_KEY]), 
                            'Incorrect number of followings for {}'.format(self._usernames[follower_index]))
            
        succeeded, result = self._pytwis.get_followers(self._auth_secrets[0])
        self.assertTrue(succeeded, 'Failed to get the follower list for {}'.format(self._usernames[0]))
        self.assertEqual(0, len(result[pytwis.pytwis_constants.FOLLOWER_LIST_KEY]), 
                        'Incorrect number of followings for {}'.format(self._usernames[0]))
        
    def test_follow(self):
        """Follow-related test routines:
        (1) _follow_unfollow_before_login
        (2) _follow_unfollow_correct_username_after_login
        (3) _follow_unfollow_wrong_username_after_login
        (4) _follow_yourself_after_login
        (5) _one_follow_multiple
        (6) _multiple_follow_one
        """
        self._follow_unfollow_before_login()
        self._follow_unfollow_correct_username_after_login()
        self._follow_unfollow_wrong_username_after_login()
        self._follow_yourself_after_login()
        self._one_follow_multiple()
        self._multiple_follow_one()


class PytwisPostFollowTests(PytwisTestsWithRegisteredUsers):
    """Test for the `Pytwis.get_timeline()` and `Pytwis.post_tweet()` functions with followers."""
    
    CNT_REGISTERED_USERS = 3
    
    def setUp(self):
        """Besides PytwisTestsWithRegisteredUsers.setUp(), we log into the users 
        and store their authentication secrets for the subsequent tests. We also 
        initialize the expected number of tweets in their timelines.
        """
        PytwisTestsWithRegisteredUsers.setUp(self)
        
        self._auth_secrets = []
        for user_index in range(0, self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.login(self._usernames[user_index], self._passwords[user_index])
            self.assertTrue(succeeded, 
                            'Failed to log into user {} with the correct password {}'.\
                            format(self._usernames[user_index], self._passwords[user_index]))
            self._auth_secrets.append(result[pytwis.pytwis_constants.AUTH_KEY])
            
        self._expected_cnt_tweets = []
        for user_index in range(self.CNT_REGISTERED_USERS):
            self._expected_cnt_tweets.append(0)
    
    def _post_after_two_follows(self):
        """Test the scenario where one user posts a tweet with two followers."""
        for follower_index in range(1, self.CNT_REGISTERED_USERS):
            succeeded, _ = self._pytwis.follow(self._auth_secrets[follower_index], self._usernames[0])
            self.assertTrue(succeeded, '{} failed to follow {}'.\
                            format(self._usernames[follower_index], self._usernames[0]))
            
        succeeded, _ = self._pytwis.post_tweet(self._auth_secrets[0], 'Tweet after two follows.')
        self.assertTrue(succeeded, '{} failed to post a tweet'.format(self._usernames[0]))
        for user_index in range(self.CNT_REGISTERED_USERS):
            self._expected_cnt_tweets[user_index] += 1
            succeeded, result = self._pytwis.get_timeline(self._auth_secrets[user_index], -1)
            self.assertTrue(succeeded, 'Failed to get the user timeline of {}'.format(self._usernames[user_index]))
            self.assertEqual(self._expected_cnt_tweets[user_index], len(result[pytwis.pytwis_constants.TWEETS_KEY]), 
                             'Incorrect number of tweets for {}'.format(self._usernames[user_index]))
    
    def _post_after_one_follow_and_one_unfollow(self):
        """Test the scenario where one user posts another tweet after one unfollow."""
        succeeded, _ = self._pytwis.unfollow(self._auth_secrets[-1], self._usernames[0])
        self.assertTrue(succeeded, '{} failed to unfollow {}'.\
                        format(self._usernames[-1], self._usernames[0]))
        
        succeeded, _ = self._pytwis.post_tweet(self._auth_secrets[0], 'Tweet after one follow and one unfollow.')
        self.assertTrue(succeeded, '{} failed to post a tweet'.format(self._usernames[0]))
        for user_index in range(self.CNT_REGISTERED_USERS):
            if user_index != self.CNT_REGISTERED_USERS - 1:
                self._expected_cnt_tweets[user_index] += 1
            succeeded, result = self._pytwis.get_timeline(self._auth_secrets[user_index], -1)
            self.assertTrue(succeeded, 'Failed to get the user timeline of {}'.format(self._usernames[user_index]))
            self.assertEqual(self._expected_cnt_tweets[user_index], len(result[pytwis.pytwis_constants.TWEETS_KEY]), 
                             'Incorrect number of tweets for {}'.format(self._usernames[user_index]))
        
    def _post_after_two_unfollows(self):
        """Test the scenario where one user posts another tweet after two unfollows."""
        succeeded, _ = self._pytwis.unfollow(self._auth_secrets[1], self._usernames[0])
        self.assertTrue(succeeded, '{} failed to unfollow {}'.\
                        format(self._usernames[1], self._usernames[0]))
        
        succeeded, _ = self._pytwis.post_tweet(self._auth_secrets[0], 'Tweet after two unfollows.')
        self.assertTrue(succeeded, '{} failed to post a tweet'.format(self._usernames[0]))
        for user_index in range(self.CNT_REGISTERED_USERS):
            if user_index == 0:
                self._expected_cnt_tweets[user_index] += 1
            succeeded, result = self._pytwis.get_timeline(self._auth_secrets[user_index], -1)
            self.assertTrue(succeeded, 'Failed to get the user timeline of {}'.format(self._usernames[user_index]))
            self.assertEqual(self._expected_cnt_tweets[user_index], len(result[pytwis.pytwis_constants.TWEETS_KEY]), 
                             'Incorrect number of tweets for {}'.format(self._usernames[user_index]))
            
    def test_post_follow(self):
        """Post-follow-coupled test routines:
        (1) _post_after_two_follows
        (2) _post_after_one_follow_and_one_unfollow
        (3) _post_after_two_unfollows
        """
        self._post_after_two_follows()
        self._post_after_one_follow_and_one_unfollow()
        self._post_after_two_unfollows()

class PytwisUserTweetsTests(PytwisTestsWithRegisteredUsers):
    """Test for the `Pytwis.get_user_tweets()` function."""
    
    CNT_REGISTERED_USERS = 2
    
    def setUp(self):
        """Besides PytwisTestsWithRegisteredUsers.setUp(), we log into the users 
        and store their authentication secrets for the subsequent tests. We also 
        initialize the expected number of tweets posted by them.
        """
        PytwisTestsWithRegisteredUsers.setUp(self)
        
        self._auth_secrets = []
        for user_index in range(0, self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.login(self._usernames[user_index], self._passwords[user_index])
            self.assertTrue(succeeded, 
                            'Failed to log into user {} with the correct password {}'.\
                            format(self._usernames[user_index], self._passwords[user_index]))
            self._auth_secrets.append(result[pytwis.pytwis_constants.AUTH_KEY])
            
        self._expected_cnt_tweets = []
        for user_index in range(self.CNT_REGISTERED_USERS):
            self._expected_cnt_tweets.append(0)

    def _get_user_tweets_without_login(self):
        """Test getting the user tweets without logged-in."""
        succeeded, result = self._pytwis.get_user_tweets('', self._usernames[0], -1)
        self.assertFalse(succeeded, 'Succeeded in getting the user tweets with an empty authentication secret.')
        self.assertEqual(pytwis.pytwis_constants.ERROR_NOT_LOGGED_IN, result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
    
    def _get_user_tweets_with_wrong_username(self):
        """Test getting the tweets of a user with a wrong username."""
        wrong_username = self._usernames[0] + '_wrong'
        succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], wrong_username, -1)
        self.assertFalse(succeeded, 'Succeeded in getting the user tweets with a wrong username.')
        self.assertEqual(pytwis.pytwis_constants.ERROR_USERNAME_NOT_EXIST_FORMAT.format(wrong_username), result[pytwis.pytwis_constants.ERROR_KEY], INCORRECT_ERROR_MSG)
    
    def _verify_user_tweets(self, cnt_tweets, username, tweets):
        """Verify if the input list `tweets` has the correct number of tweets 
        and if each tweet is posted by the expected user. 
        """
        self.assertEqual(cnt_tweets, len(tweets), 'Incorrect number of tweets posted by {}'.format(username))
        for tweet in tweets:
            self.assertEqual(username, tweet[pytwis.pytwis_constants.USERNAME_KEY], 'Mismatched username')

    def _get_user_tweets_without_follow(self):
        """Test getting the tweets of two users where they don't follow each other."""
        for user_index in range(self.CNT_REGISTERED_USERS):
            self._expected_cnt_tweets[user_index] += 10
            for tweet_index in range(0, self._expected_cnt_tweets[user_index]):
                succeeded, _ = self._pytwis.post_tweet(self._auth_secrets[user_index], 
                                                       'Tweet {} without follow'.format(tweet_index))
                self.assertTrue(succeeded, '{} failed to post a tweet'.format(self._usernames[user_index]))
                
        for user_index in range(self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], self._usernames[user_index], -1)
            self.assertTrue(succeeded, '{} failed to get the tweets of {}'.\
                            format(self._usernames[0], self._usernames[user_index]))
            self._verify_user_tweets(self._expected_cnt_tweets[user_index], self._usernames[user_index], result[pytwis.pytwis_constants.TWEETS_KEY])
    
    def _get_user_tweets_with_follow(self):
        """Test getting the tweets of two users where one user follows the other."""
        succeeded, _ = self._pytwis.follow(self._auth_secrets[0], self._usernames[1])
        self.assertTrue(succeeded, '{} failed to follow {}'.format(self._usernames[0], self._usernames[1]))
        
        self._expected_cnt_tweets[1] += 10
        for tweet_index in range(0, 10):
            succeeded, _ = self._pytwis.post_tweet(self._auth_secrets[1], 
                                                   'Tweet {} with follow'.format(tweet_index))
            self.assertTrue(succeeded, '{} failed to post a tweet'.format(self._usernames[1]))
        
        for user_index in range(self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], self._usernames[user_index], -1)
            self.assertTrue(succeeded, '{} failed to get the tweets of {}'.\
                            format(self._usernames[0], self._usernames[user_index]))
            self._verify_user_tweets(self._expected_cnt_tweets[user_index], self._usernames[user_index], result[pytwis.pytwis_constants.TWEETS_KEY])
    
    def _get_zero_user_tweet(self):
        """Test getting zero user tweet."""
        for user_index in range(self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], self._usernames[user_index], 0)
            self.assertTrue(succeeded, '{} failed to get the tweets of {}'.\
                            format(self._usernames[0], self._usernames[user_index]))
            self._verify_user_tweets(0, self._usernames[user_index], result[pytwis.pytwis_constants.TWEETS_KEY])
    
    def _get_fewer_user_tweets(self):
        """Test getting user tweets fewer than available ones."""
        for user_index in range(self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], 
                                                             self._usernames[user_index], 
                                                             self._expected_cnt_tweets[user_index]//2)
            self.assertTrue(succeeded, '{} failed to get the tweets of {}'.\
                            format(self._usernames[0], self._usernames[user_index]))
            self._verify_user_tweets(self._expected_cnt_tweets[user_index]//2, 
                                     self._usernames[user_index], 
                                     result[pytwis.pytwis_constants.TWEETS_KEY])

    def _get_more_user_tweets(self):
        """Test getting user tweets more than available ones."""
        for user_index in range(self.CNT_REGISTERED_USERS):
            succeeded, result = self._pytwis.get_user_tweets(self._auth_secrets[0], 
                                                             self._usernames[user_index], 
                                                             self._expected_cnt_tweets[user_index]*2)
            self.assertTrue(succeeded, '{} failed to get the tweets of {}'.\
                            format(self._usernames[0], self._usernames[user_index]))
            self._verify_user_tweets(self._expected_cnt_tweets[user_index], 
                                     self._usernames[user_index], 
                                     result[pytwis.pytwis_constants.TWEETS_KEY])

    def test_get_user_tweets(self):
        """Get-user-tweets test routines:
        (1) _get_user_tweets_without_login
        (2) _get_user_tweets_with_wrong_username
        (3) _get_user_tweets_without_follow
        (4) _get_user_tweets_with_follow
        (5) _get_zero_user_tweet
        (6) _get_fewer_user_tweets
        (7) _get_more_user_tweets
        """
        self._get_user_tweets_without_login()
        self._get_user_tweets_with_wrong_username()
        self._get_user_tweets_without_follow()
        self._get_user_tweets_with_follow()
        self._get_zero_user_tweet()
        self._get_fewer_user_tweets()
        self._get_more_user_tweets()


class PytwisSocketTests(unittest.TestCase):
    """Test for connecting to the Redis server via the UNIX domain socket."""
    
    def test_connect_socket(self):
        """Test connecting to the Redis server via socket."""
        try:
            self._pytwis = pytwis.Pytwis(socket='/tmp/redis.sock', db=TEST_DATABASE_ID)
        except ValueError as e:
            self.fail('Failed to connect to the Redis server via socket: {}'.format(str(e)))


if __name__ == '__main__':
    unittest.main()