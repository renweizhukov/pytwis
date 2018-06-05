# -*- coding: utf-8 -*-
"""This module provides a workaround for importing pytwis from
the parent directory.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytwis  # pylint: disable=wrong-import-position,unused-import
