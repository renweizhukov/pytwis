# -*- coding: utf-8 -*-

"""A setuptools-based setup module.

See:
https://github.com/renweizhukov/pytwis
"""

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()
    

setup(
    name='pytwis',
    version='0.2.0',
    description='A twitter-toy-clone backend using Python and Redis',
    long_description=long_description,
    url='https://renweizhukov.github.io/pytwis',
    author='Wei Ren',
    author_email='renwei2004@gmail.com',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Database :: Database Engines/Servers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.6',
        ],
    keywords='redis twitter python3.6',
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=['parse', 'redis'],
    # This project depends on a built-in module `secrets` only available 
    # in Python 3.6 and later,
    python_requires='>=3.6',
    extras_require={
        'test': ['coverage']
        },
    entry_points={
        'console_scripts': [
            'pytwis_clt=pytwis.pytwis_clt:pytwis_cli'
        ],
        },
    project_urls={
        'Bug Reports': 'https://github.com/renweizhukov/pytwis/issues',
        'Documentation': 'https://renweizhukov.github.io/pytwis',
        'Source': 'https://github.com/renweizhukov/pytwis',
        },
    )