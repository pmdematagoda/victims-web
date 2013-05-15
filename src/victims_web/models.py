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
Data models.
"""

import datetime
import re

from mongokit import ValidationError, CustomType

from flask.ext.mongokit import Document


class RegExValidator(object):

    def __init__(self, rx, is_list=False, is_dict=False):
        self.__rx_str = rx
        self.__rx = re.compile(rx)
        self.__is_list = is_list
        self.__is_dict = is_dict

    def _validate(self, item):
        if bool(self.__rx.match(item)):
            return True
        raise ValidationError('%s must match ' + self.__rx_str)

    def __call__(self, value):
        if self.__is_list:
            for item in value:
                self._validate(item)
        elif self.__is_dict:
            for k, v in value.items():
                if self.__is_dict.lower() == 'key':
                    self._validate(k)
                else:
                    self._validate(v)
        else:
            self._validate(value)
        return True


class SerializableDate(CustomType):

    mongo_type = datetime.datetime
    python_type = basestring
    init_type = datetime.datetime.utcnow

    def to_bson(self, value):
        """convert type to a mongodb type"""
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")

    def to_python(self, value):
        """convert type to a python object"""
        if value is not None:
            return value.isoformat()


class Hash(Document):
    __collection__ = 'hashes'

    structure = {
        'date': SerializableDate(),
        'name': basestring,
        'version': basestring,
        'format': basestring,
        'hashes': {
            basestring: {
                'files': dict,
                'combined': basestring
            }
        },
        'vendor': basestring,
        'cves': dict,
        'status': basestring,
        'meta': list,
        'submitter': basestring,
        'submittedon': SerializableDate()
    }
    use_dot_notation = True
    required_fields = [
        'name', 'version', 'format',
        'status', 'cves', 'submitter']
    default_values = {
        'status': u'SUBMITTED',
        'vendor': u'UNKNOWN',
        'version': u'UNKNOWN',
        'hashes': {},
        'submittedon': SerializableDate(),
        'meta': [],
    }
    validators = {
        'name': RegExValidator('^[a-zA-Z0-9_\-\.]*$'),
        'version': RegExValidator('^[a-zA-Z0-9_\-\.]*$'),
        'format': RegExValidator('^[a-zA-Z0-9\-]*$'),
        'vendor': RegExValidator('^[a-zA-Z0-9_ \-]*$'),
        'cves': RegExValidator('^CVE-\d{4}-\d{4}$', is_dict='key'),
        'submitter': RegExValidator('^[a-zA-Z0-9]*$'),
    }


class Account(Document):
    __collection__ = 'users'

    structure = {
        'username': basestring,
        'password': basestring,
        'endorsements': list,
        'active': bool,
        'createdon': datetime.datetime,
        'lastlogin': datetime.datetime,
        'lastip': basestring,
    }

    use_dot_notation = True
    required_fields = ['username', 'password']

    default_values = {
        'endorsements': [],
        'active': False,
        'lastlogin': datetime.datetime.utcnow(),
        'createdon': datetime.datetime.utcnow(),
        'lastip': None,
    }
    validators = {
        'username': RegExValidator('^[a-zA-Z0-9]*$'),
    }


# Place all models that should get registered in MODELS
MODELS = [Hash, Account]
