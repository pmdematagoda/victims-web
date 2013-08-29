# This file is part of victims-web.
#
# Copyright (C) 2013 Dulitha Ranatunga
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
Search Database 
"""

import datetime
import os.path
import re

from flask import (
    Blueprint, current_app, render_template, helpers,
    url_for, request, redirect, flash)
from werkzeug import secure_filename

from flask.ext import login

from victims_web.errors import ValidationError
from victims_web.models import Hash
from victims_web.cache import cache

from mongoengine import (StringField, DateTimeField, DictField,
                         BooleanField)

dbSearch = Blueprint('dbSearch', __name__,template_folder='templates')  

@dbSearch.route('/search', methods=['GET','POST'])
@cache.memoize()
def search(query=None):
    from flask.ext.mongoengine import Document
    """
    excluded = dir(Document)
    excluded.extend(['_v1','_pre_save_hooks','DoesNotExist','MultipleObjectsReturned','jsonify','_auto_id_field'])
    
    #
    acceptedFields = []#should match up with Hash in models.py}
    
    allFields = dir(Hash)
    for field in allFields:
        if field not in excluded:
            acceptedFields.append(field)
    
   """
    acceptedFields = ['name','cves','submitter','format','vendor','status']
    hashFields=['sha512','sha256','md5']
    acceptedFields.extend(hashFields)
    searchString=  ""
    
    #Note to self:: look into Q objects for complex queries:
    #https://docs.djangoproject.com/en/dev/topics/db/queries/
    hashes = Hash.objects()
    if request.method == 'POST':
    #filter results
        
        searchField = request.form.get('field','name')
        searchString = request.form.get('searchString','')
        
        if searchField in hashFields:
            lookup = "hashes__%s__combined__icontains" % searchField
            flash(lookup)
            hashes = hashes.filter(**{lookup: searchString})
        else:
            if isinstance(getattr(Hash,searchField),StringField):
                lookup = "%s__icontains" % searchField    
            else:
                lookup = searchField
            hashes = hashes.filter(**{lookup: searchString})
            
        #keep search string and field after search
        fieldId = acceptedFields.index(searchField)
        #reorder dropdown menu
        for i in xrange(fieldId):
            acceptedFields[fieldId-i] = acceptedFields[fieldId-i-1]
        acceptedFields[0] = searchField
         
    
    data={
            'hashes': hashes,
            'numResults': len(hashes),
            'acceptedFields': acceptedFields,
            'searchString': searchString
        }

    return render_template('search.html', **data)