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
Victims Forms Handler
"""

from flask import flash
from flask_wtf import Form, RecaptchaField
from wtforms import fields, validators, ValidationError

from victims_web.config import (
    SUBMISSION_GROUPS, DEBUG, HASHING_COMMANDS, TESTING)
from victims_web.models import Account


def is_field_value(form, fieldname, value, negate=False):
    """
    Helper function to check if the given field in the given form is of a
    specified value.

    :Parameters:
        - `form`: The form the test on
        - `fieldname`: The fieldname to test value against. If not found an
        Exception is raised.
        - `value`: Value to test for.
        - `negate`: True/False to invert the result.
    """
    field = form._fields.get(fieldname)
    if field is None:
        raise Exception('Invalid field "%s"' % fieldname)
    test = value == field.data
    test = not test if negate else test
    return test


class RequiredIf(validators.Required):
    """
    Custom validator to enforce requires only if another field matches a
    specified value. the `negate` allows for inverting the result.
    """
    def __init__(self, other_fieldname, value, negate, *args, **kwargs):
        self.other_fieldname = other_fieldname
        self.negate = negate
        self.value = value
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        if is_field_value(form, self.other_fieldname, self.value, self.negate):
            super(RequiredIf, self).__call__(form, field)


class ValidateOnlyIf(RequiredIf):
    """
    Custom validator that build around the RequiredIf validator. The given
    validators are only run if a given value test fails.
    """
    def __init__(self, validators, *args, **kwargs):
        self.validators = validators
        super(ValidateOnlyIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        if is_field_value(form, self.other_fieldname, self.value, self.negate):
            for validator in self.validators:
                validator.__call__(form, field)


class RequiredIfNoneValid(validators.Required):
    """
    Custom validator to enforce required only if none of the validators
    provided are valid.
    """
    def __init__(self, validators, *args, **kwargs):
        self.validators = validators
        super(RequiredIfNoneValid, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        for validator in self.validators:
            try:
                validator.__call__(form, field)
                return
            except ValidationError:
                pass
        super(RequiredIfNoneValid, self).__call__(form, field)


class GroupSelectField(fields.SelectField):
    """
    Custom field to handle group selection
    """
    DEFAULT_GROUP = '---'
    VALID_GROUPS = SUBMISSION_GROUPS.keys()

    def __init__(self, validators, *args, **kwargs):
        super(GroupSelectField, self).__init__('Group', *args, **kwargs)
        self.choices = [(self.DEFAULT_GROUP, 'unset')]
        for group in self.VALID_GROUPS:
            self.choices.append((group, group))
        self.validators = validators


class GroupRequired(validators.Required):
    """
    Custom validator for the archive submission form.
    """
    def __init__(self, groupfield, *args, **kwargs):
        self.groupfield = groupfield
        super(GroupRequired, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        group = form._fields.get(self.groupfield).data
        if field.label.field_id.split('_', 1)[0] == group:
            super(GroupRequired, self).__call__(form, field)


class GroupHashable():
    """
    Custom validator to check if a group is hashable
    """
    def __init__(self, groupfield, *args, **kwargs):
        self.groupfield = groupfield

    def __call__(self, form, field):
        group = form._fields.get(self.groupfield).data
        if group not in HASHING_COMMANDS.keys():
            msg = 'Group "%s" cannot be hashed' % (group)
            flash(msg, 'error')
            raise ValidationError(msg)


class HasFile():
    """
    Validator to check if the form has a file in a given field
    """
    def __init__(self, filefield):
        self.filefield = filefield

    def __call__(self, form, field):
        filename = form._fields.get(self.filefield).data.filename.strip()
        if len(filename) == 0:
            raise ValidationError('No file provided')


class Password():
    """
    Password Validator
    """
    def __init__(self, username_field='username'):
        self.username_field = username_field

    def __call__(self, form, field):
        username = form._fields.get(self.username_field)
        password = field.data
        if username:
            username = username.data
            if password == username:
                raise ValidationError(
                    'Password can not be the same as the username.')

        for char in password:
            cnt = password.count(char)
            if cnt / float(len(password)) > 0.3:
                raise ValidationError((
                    'You can not use the same '
                    'char for more than 30% of the password'))

        if len(password) <= 8:
            raise ValidationError('Password too simple.')


class UserName():
    """
    Username Validator
    """
    def __call__(self, form, field):
        if Account.objects(username=field.data).first():
            raise ValidationError('Username is not available.')


class ArchiveSubmit(Form):
    """
    Archive submission form
    """
    cves = fields.StringField('CVE(s)', validators=[
        validators.Regexp(
            '^CVE-\d+-\d+(\s*,\s*CVE-\d+-\d+)*$',
            message='Invalid CVE. Multiple CVEs can seperated with commas.'
        ),
        validators.required(),
    ])
    archive = fields.FileField('Archive')
    group = GroupSelectField([validators.AnyOf(GroupSelectField.VALID_GROUPS)])
    for (g, fs) in SUBMISSION_GROUPS.items():
        if len(fs) > 0:
            for f in fs:
                validator = RequiredIfNoneValid([
                    HasFile('archive'), GroupRequired('group')])
                field = fields.StringField(f, [validator])
                exec('%s_%s = field' % (g, f))


class RegistrationForm(Form):
    """
    Registration Form
    """
    username = fields.StringField('Username',  [
        validators.Regexp('^[\w\.]*$', message='Invalid Username'),
        validators.required(),
        UserName(),
    ])
    password = fields.PasswordField('Password', [
        validators.required(),
        validators.EqualTo('verify_password', 'Passwords do not match.'),
        Password('username'),
    ])
    verify_password = fields.PasswordField('Verify Password')
    email = fields.StringField('Email')

    if not (DEBUG or TESTING):
        recaptcha = RecaptchaField()
    else:
        recaptcha = fields.HiddenField('Recaptcha')


class AccountEditForm(Form):
    """
    Edit user account information
    """
    change_password = fields.BooleanField('Update Password')
    password = fields.PasswordField('New Password', [
        validators.required(),
        validators.EqualTo('verify_password', 'Passwords do not match.'),
        Password('username'),
    ])
    verify_password = fields.PasswordField('Verify Password')
    change_email = fields.BooleanField('Update Email')
    email = fields.StringField('Email')
    regenerate = fields.BooleanField('Regenereate API tokens')


def flash_errors(form):
    """
    Flashes form error messages
    Source: http://stackoverflow.com/q/13585663/1874604
    """
    for field, errors in form.errors.items():
        for error in errors:
            flash('%s - %s' % (
                getattr(form, field).label.text,
                error
            ), 'error')
