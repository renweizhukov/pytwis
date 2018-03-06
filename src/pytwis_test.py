#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pytwis import Pytwis

# By default the database index ranges from 0 to 15.
TEST_DATABASE_ID = 15

class PytwisRegisterTests(unittest.TestCase):
    '''Test for the ``Pytwis.register()`` function.'''
    
    USERNAME = 'test_username'
    PASSWORD = 'test_password'
    
    def setUp(self):
        '''Set up the register test.
        
        (1) Connect to the test database of the local Redis server.
        
        (2) Delete all the keys of the test database via ``flushdb``. 
        Note that do NOT use ``flushall` which will delete all the 
        keys of all the existing databases. 
        '''
        try:
            self._pytwis = Pytwis(db=TEST_DATABASE_ID)
        except ValueError as e:
            self.fail('Failed to connect to the Redis server: {}'.format(str(e)))
            
        self._pytwis._rc.flushdb()
    
    def tearDown(self):
        '''Clean up after the register test is done.
        
        Delete all the keys of the test database
        '''
        self._pytwis._rc.flushdb()
        
    def test_registerNewAndExistingUsers(self):
        '''Register a new user and then an existing user.'''
        succeeded, _ = self._pytwis.register(self.USERNAME, self.PASSWORD)
        self.assertTrue(succeeded, 'Succeeded in registering a new username')
        
        succeeded, result = self._pytwis.register(self.USERNAME, self.PASSWORD)
        self.assertFalse(succeeded, 'Failed to register an existing username')
        self.assertEqual(result['error'], 'username {} already exists'.format(self.USERNAME), 
                         'Incorrect error message')
        
if __name__ == '__main__':
    unittest.main()