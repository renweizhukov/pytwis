#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pytwis import Pytwis

# By default the database index ranges from 0 to 15.
TEST_DATABASE_ID = 15

class PytwisTests(unittest.TestCase):
    '''Pytwis test base class which has the general setUp() and tearDown() methods.'''
    
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

class PytwisRegisterTests(PytwisTests):
    '''Test for the ``Pytwis.register()`` function.'''
    
    def registerNewAndExistingUsers(self):
        '''Register a new user and then an existing user.'''
        username = 'test_username'
        password = 'test_password'
        succeeded, _ = self._pytwis.register(username, password)
        self.assertTrue(succeeded, 'Succeeded in registering a new username')
        
        succeeded, result = self._pytwis.register(username, password)
        self.assertFalse(succeeded, 'Failed to register an existing username')
        self.assertEqual(result['error'], 'username {} already exists'.format(username), 
                         'Incorrect error message')
        
    def registerSameUserAtSameTime(self):
        '''Register the same user in two threads almost simultaneously.'''
        username = 'test2_username'
        password = 'test2_password'
        
        from multiprocessing.pool import ThreadPool
        pool = ThreadPool(processes=1)
        
        async_result1 = pool.apply_async(self._pytwis.register, (username, password))
        async_result2 = pool.apply_async(self._pytwis.register, (username, password))
        
        succeeded1, _ = async_result1.get()
        succeeded2, _ = async_result2.get()
        
        self.assertTrue(succeeded1 != succeeded2, 'One register should succeed and the other register should fail')
        
    def test_register(self):
        self.registerNewAndExistingUsers()
        self.registerSameUserAtSameTime()
        
if __name__ == '__main__':
    unittest.main()