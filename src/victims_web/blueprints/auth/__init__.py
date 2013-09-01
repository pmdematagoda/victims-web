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
Authentication related views.
"""

from flask import (
    Blueprint, current_app, escape, flash, render_template, request,
    url_for, redirect)

from flask.ext.login import fresh_login_required, login_required, current_user
from recaptcha.client import captcha
from mongoengine import ValidationError

from victims_web.blueprints.helpers import safe_redirect_url
from victims_web.handlers.identity import login, logout
from victims_web.user import create_user, get_account
from victims_web.models import Account

auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route("/login", methods=['GET', 'POST'])
def login_user():
    def redirect_url():
        forward = safe_redirect_url()
        if not forward:
            flash("Logged in successfully.", category='info')
        return redirect(forward or url_for('ui.index'))

    # If you are already logged in, go away!
    if not current_user.is_anonymous():
        return redirect_url()

    if request.method == 'POST':
        username = request.form.get('username', '')
        if login(username, request.form.get('password', '')):
            return redirect_url()

        flash("Invalid username/password", category='error')

    return render_template("login.html")


@auth.route("/logout", methods=['GET'])
@login_required
def logout_user():
    logout()
    return redirect(url_for('ui.index'))


@auth.route('/account', methods=['GET'])
@login_required
def user_account():
    account = get_account(current_user.username)
    content = {
        'username': account.username,
        'email': account.email,
        'apikey': str(account.apikey),
        'secret': str(account.secret),
    }
    return render_template('account.html', **content)


def validate_password(username=None):
    # Password checks to make sure they are at least somewhat sane
    for char in request.form['password']:
        cnt = request.form['password'].count(char)
        if cnt / float(len(request.form['password'])) > 0.3:
            raise ValueError((
                'You can not use the same '
                'char for more than 30% of the password'))
        if not username:
            username = request.form['username']
        if request.form['password'] == username:
            raise ValueError(
                'Password can not be the same as the username.')
        if len(request.form['password']) <= 8:
            raise ValueError('Password to simple.')
        if request.form['password'] != request.form['verify_password']:
            raise ValueError('Passwords do not match.')


def validate_username():
    if Account.objects(username=request.form['username']).first():
        raise ValueError('Username is not available.')


def validate_captcha():
    if (not current_app.config['DEBUG'] or not current_app.config['TESTING']):
        # First things first, test the captcha
        response = captcha.submit(
            request.form['recaptcha_challenge_field'],
            request.form['recaptcha_response_field'],
            current_app.config['RECAPTCHA_PRIVATE_KEY'],
            request.remote_addr,
        )
        if not response.is_valid:
            raise ValueError('Captcha did not match.')


@auth.route('/account_edit', methods=['GET', 'POST'])
@login_required
@fresh_login_required
def user_edit():
    if request.method == 'POST':
        try:
            account = get_account(current_user.username)

            if request.form.get('change_password', 'off') == 'on':
                validate_password(account.username)
                account.set_password(request.form['password'])

            if request.form.get('change_email', 'off') == 'on':
                account.email = request.form['email'].strip()

            if request.form.get('regenerate', 'off') == 'on':
                account.update_api_tokens()

            account.validate()
            account.save()
            flash('Account information was successfully updated!',
                  category='info')
            return redirect(url_for('auth.user_account'))
        except ValueError as ve:
            flash(ve.message, category='error')
        except ValidationError as ve:
            invalids = ','.join([f.title() for f in ve.errors.keys()])
            msg = 'Invalid: %s' % (invalids)
            flash(escape(msg), category='error')
        except Exception as ex:
            current_app.logger.info(ex)
            flash('An unknown error has occured.', category='error')

    return render_template('account_edit.html')


@auth.route("/register", methods=['GET', 'POST'])
def register_user():

    fields = {
        'Username': {'name': 'username', 'req': True},
        'Password': {'name': 'password', 'type': 'password', 'req': True},
        'Verify Password': {'name': 'verify_password', 'type': 'password',
                            'req': True},
        'Email': {'name': 'email', 'type': 'email'},
    }

    # Someone with a session can not make a new user
    if current_user.is_authenticated():
        flash(
            'You are already logged in as %s' % (
                escape(current_user.username)),
            category='info')
        return redirect(url_for('ui.index'))

    # Request to make a new user
    if request.method == 'POST':
        try:
            for fname in fields:
                field = fields[fname]
                if field.get('req', False):
                    key = field['name']
                    if (key not in request.form.keys() or
                            len(request.form[key].strip()) == 0):
                        raise ValueError('%s is required' % (fname))

            # perform validation
            validate_captcha()
            validate_username()
            validate_password()

            email = request.form.get('email', '').strip()
            email = None if len(email) == 0 else email
            user = create_user(
                request.form['username'],
                request.form['password'],
                email=email)
            login(request.form['username'], request.form['password'])
            flash('Registration successful, welcome %s!' % (user.username),
                  category='info')
            return redirect(url_for('ui.index'))
        except ValidationError, ve:
            invalids = ','.join([f.title() for f in ve.errors.keys()])
            msg = 'Invalid: %s' % (invalids)
            flash(escape(msg), category='error')
        except ValueError, ve:
            flash(escape(ve.message), category='error')
        except (KeyError, IndexError):
            flash('Missing information.', category='error')
        except Exception, ex:
            current_app.logger.info(ex)
            flash('An unknown error has occured.', category='error')

    # Default
    recaptcha = {
        'public_key': current_app.config['RECAPTCHA_PUBLIC_KEY'],
        'theme': current_app.config['RECAPTCHA_THEME'],
    }
    return render_template('register.html', recaptcha=recaptcha, fields=fields)
