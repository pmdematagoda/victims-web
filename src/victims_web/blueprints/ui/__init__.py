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
Main web ui.
"""

import re

from flask import (
    Blueprint, current_app, escape, render_template, helpers,
    url_for, request, redirect, flash)

from flask.ext import login

from victims_web.cache import cache
from victims_web.config import SUBMISSION_GROUPS
from victims_web.errors import ValidationError
from victims_web.handlers.forms import ArchiveSubmit, flash_errors
from victims_web.models import Hash
from victims_web.plugin.crosstalk import indexmon
from victims_web.submissions import submit, upload


ui = Blueprint(
    'ui', __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/')  # Last argument needed since we register on /


def _is_hash(data):
    """
    Verifies the hash is a sha1 hash.
    """
    if re.match('^([a-zA-Z0-9]{128})$', data):
        return True
    return False


@ui.route('/', methods=['GET'])
def index():
    _cache_key = 'view/%s/get_data' % (request.path)

    @cache.cached(key_prefix=_cache_key)
    def get_data():
        indexmon.refresh(True)
        return indexmon.get_data()

    if indexmon.refreshed_flag:
        cache.delete(_cache_key)
        indexmon.refreshed_flag = False
    return render_template('index.html', **get_data())


@ui.route('/hashes/', methods=['GET'])
@cache.memoize()
def hashes(format=None):
    hashes = Hash.objects(status='RELEASED')

    group = request.args.get('group', 'all')
    if group != 'all':
        if format not in Hash.objects.distinct('group'):
            flash('Group of hashes not found', 'error')
        else:
            hashes = hashes.filter(group=group)

    return render_template('hashes.html', hashes=hashes)


@ui.route('/hash/<hash>/', methods=['GET'])
def hash(hash):
    if _is_hash(hash):
        a_hash = Hash.objects.get_or_404(hashes__sha512__combined=hash)
        return render_template('onehash.html', hash=a_hash)
    flash('Not a valid hash', 'error')
    return redirect(url_for('ui.hashes'))


def process_submission(form):
    try:
        cves = []
        for cve in form.cves.data.split(','):
            cves.append(cve.strip())

        group = form.group.data
        meta = {}
        for field in SUBMISSION_GROUPS.get(group, []):
            value = form._fields.get('%s_%s' % (group, field)).data.strip()
            if len(value) > 0:
                meta[field] = value

        files = upload(group, request.files.get('archive', None), meta)
        for (ondisk, filename, suffix) in files:
            submit(login.current_user.username, ondisk, group, filename,
                   suffix, cves, meta)

        current_app.config['INDEX_REFRESH_FLAG'] = True

        flash('Archive Submitted for processing', 'info')
    except ValueError, ve:
        flash(escape(ve.message), 'error')
    except ValidationError, ve:
        flash(escape(ve.message), 'error')
    except OSError, oe:
        flash('Could not upload file due to a server side error', 'error')
        current_app.logger.debug(oe)


@ui.route('/submit/archive/', methods=['GET', 'POST'])
@login.login_required
def submit_archive():
    form = ArchiveSubmit()
    if form.validate_on_submit():
        process_submission(form)
        return redirect(url_for('ui.index'))
    elif request.method == 'POST':
        flash_errors(form)
    return render_template(
        'submit_archive.html', form=form, groups=SUBMISSION_GROUPS.keys())


@ui.route('/<page>.html', methods=['GET'])
def static_page(page):
    # These are the only 'static' pages
    if page in ['about', 'client', 'bugs']:
        return render_template('%s.html' % page)
    return helpers.NotFound()
