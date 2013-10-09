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
    
stringFields = {'name':"",'version':"",'format':"",'submitter':"",'vendor':"",'cve':""}
hashFields={'sha512':"",'sha256':"",'md5':""}
checkFields={'group':['java','python','ruby'], 'status':['submitted','released']}

    


@dbSearch.route('/search', methods=['GET','POST'])
@cache.memoize()
def search(query=None):
    from flask.ext.mongoengine import Document
    """
    excluded = dir(Document)
    excluded.extend(['_v1','_pre_save_hooks','DoesNotExist','MultipleObjectsReturned','jsonify','_auto_id_field'])
    
    #
    acceptedFields = []#should match up with Hash in models.py}
    
    
   """
    advanced="none"
    acceptedFields = {'name':"",'cves':"",'submitter':"",'format':"",'vendor':"",'status':""}
    hashFields=['sha512','sha256','md5']
    for hashType in hashFields:
        acceptedFields[hashType]=""
    searchString=  ""
    hashes = Hash.objects()
    dateSearchValues={}
    if request.method == 'POST':
    #filter results
        if 'advSearch' in request.form:
            #Advanced Search
            from mongoengine.queryset import Q
            #Create search filter on accepted fields
            lookup = Q()
            
            for field in acceptedFields.keys():
                #getData
                
                searchString = request.form.get(field+"_searchString",'')
                acceptedFields[field]= searchString
                
                if field in hashFields:
                    field = "hashes__%s__combined" % field
                
                if len(searchString) > 0:
                    option = request.form.get(field+"_searchOption","contains")
                    if option == "contains":
                       lookup = lookup & Q(**{"%s__icontains" % field:searchString})
                    elif option == "exact":
                       lookup = lookup & Q(**{"%s__iexact" % field:searchString})
                    elif option == "any":
                       for term in searchString.split():
                        lookup = lookup | Q(**{"%s__icontains" % field:term})
            
            #Extend search filter to date time
            day=request.form.get('date_day',"2013")
            month=request.form.get('date_month',"1")
            year=request.form.get('date_year',"1")
            option=request.form.get('date_option','any')
            dateSearchValues['date_day_val']=day
            dateSearchValues['date_month_val']=month
            dateSearchValues['date_year_val']=year
            
            day = 1 if day=="" else int(day)
            month = 1 if month=="" else int(month)
            year = 2013 if year=="" else int(year)
            date = datetime.datetime(year,month,day)
            if option =='on':
                dateLookup = Q(submittedon=date)
            elif option =='before':
                dateLookup = Q(submittedon__lte=date)
            elif option =='after':
                dateLookup = Q(submittedon__gte=date)
            else:
                dateLookup = Q()
                
            
            lookup = lookup  & dateLookup
            
            #filter by them
            
            
            hashes = Hash.objects.filter(lookup)
            advanced="block"
        else:
            #Simple Search        
            searchField = request.form.get('field','name')
            searchString = request.form.get('searchString','')
            
            if searchField in hashFields:
                lookup = "hashes__%s__combined__icontains" % searchField
                hashes = hashes.filter(**{lookup: searchString})
            else:
                if isinstance(getattr(Hash,searchField),StringField):
                    lookup = "%s__icontains" % searchField    
                else:
                    lookup = searchField
                hashes = hashes.filter(**{lookup: searchString})
                
            #keep search string and field after search
            """
            fieldId = acceptedFields.index(searchField)
            #reorder dropdown menu
            for i in xrange(fieldId):
                acceptedFields[fieldId-i] = acceptedFields[fieldId-i-1]
            acceptedFields[0] = searchField
            
            """
            advanced="none"
    
    
    data={
            'hashes': hashes,
            'numResults': len(hashes),
            'acceptedFields': acceptedFields,
            
            'searchString': searchString,
            'advanced':advanced
            
        }
        
    data.update(dateSearchValues);    

    return render_template('search.html', **data)