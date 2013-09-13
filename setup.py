#!/usr/bin/env python
#
# This file is part of victims-web.
#
# Copyright (C) 2013 The Victims Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Source build and installation script.
"""

from setuptools import setup


setup(
    name='victims_web',
    version='2.0.1',
    description='The victi.ms language package to CVE service.',
    author='Steve Milner',
    url='http://www.victi.ms',

    dependency_links=[
        'https://github.com/mrjoes/flask-admin/tarball/f164aeb/'
        + '#egg=Flask-Admin-1.0.7dev',
    ],

    install_requires=[
        'Flask>=0.10',
        'Flask-Admin>=1.0.6',
        'Flask-Bcrypt',
        'Flask-Cache',
        'Flask-Login>=0.1.1',
        'Flask-MongoEngine',
        'Flask-SeaSurf',
        'Flask-SSLify',
        'Flask-Views',
        'Flask-WTF>=0.9.1',
        'blinker',
        'PyYAML',
        'requests',
    ],
)
