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
from flask.ext.mongoengine import Document

from mongoengine.queryset import Q

from mongoengine import (StringField, DateTimeField, DictField,
                         BooleanField)

dbSearch = Blueprint('dbSearch', __name__,template_folder='templates')  
    
stringFields = {'name':"",'version':"",'format':"",'submitter':"",'vendor':"",'cve':""}
hashFields={'sha512':"",'sha256':"",'md5':""}
checkFields={'group':{'java':True,'python':False,'ruby':False}, 'status':{'submitted':False,'released':False}}
dateFields={'date_day_val':"",'date_month_val':"",'date_year_val':""}
hashCheckBoxes={}
for hashType in hashFields.keys():
    hashCheckBoxes[hashType]=[True,False]
printFields={'name','version','hashes.sha512.combined'}
   

def getOrderedStringFields(default=None):
    list = stringFields.keys()
    list.extend(hashFields.keys())
    list.sort()
    if default is not None:
        list.remove(default)
        temp = [str(default)]
        temp.extend(list)
        list = temp
    return list

def sanitised(string):
    """Sanitises a string against nosql injection errors. 
    Returns 1 if safe, else 0"""
    return 1
    
def basicSearch(searchField,searchString):
    """Does a basic search of the database, specific to one field at a
    time, any hash searches only checked the combined field."""
    if not sanitised(searchString):
        return (False,"Invalid Input", [])
    
    if len(searchString) == 0:
        return (False,"",[])
        
    hashes = Hash.objects()
    if searchField in hashFields:
            lookup = "hashes__%s__combined__icontains" % searchField
            hashes = hashes.filter(**{lookup: searchString})
    elif searchField == 'cve':         
            lookup = "cves__id__icontains"
            hashes = hashes.filter(**{lookup: searchString})
    else:
        if isinstance(getattr(Hash,searchField),StringField):
            lookup = "%s__icontains" % searchField    
        else:
            lookup = searchField
        hashes = hashes.filter(**{lookup: searchString})

    if (len(hashes) == 0):
        return (False,"No Results Found",[])
    else:
        return (True,str(len(hashes)) + " Results Found",hashes)


def stringQuery(field,searchString,lookup):        
    option = request.form.get(field+"_searchOption","contains")
    if option == "contains":
       lookup = lookup & Q(**{"%s__icontains" % field:searchString})
    elif option == "exact":
       lookup = lookup & Q(**{"%s__iexact" % field:searchString})
    elif option == "any":
       for term in searchString.split():
        lookup = lookup | Q(**{"%s__icontains" % field:term})

    return lookup
            
def SetHashCheckedBoxes(field):
    checkedBoxes= request.form.getlist('%s_combined'%field)
    checkedBoxes = [str(x) for x in checkedBoxes]
    if 'Combined' in checkedBoxes:
        hashCheckBoxes[field][0]=True
    else:
        hashCheckBoxes[field][0]=False
    if 'All' in checkedBoxes:
        hashCheckBoxes[field][1]=True
    else:
        hashCheckBoxes[field][1]=False    
    
    
def advancedSearch():
    lookup = Q()
    
    filterFields = []    
    
    for field in checkFields.keys():
        #Update checkFields
        checkedBoxes=request.form.getlist(field)
        checkedBoxes = [str(x) for x in checkedBoxes]
        checkeredLookup = Q()
        for key in checkFields[field].keys():
            fieldSelected = False
            if key in checkedBoxes:
                checkFields[field][key]=True
                checkeredLookup = checkeredLookup | Q(**{"%s__iexact" % field: key})
                fieldSelected = True
            else:
                checkFields[field][key]=False
            
            if fieldSelected:
                filterFields.append(field)
        lookup = lookup & checkeredLookup
    
    #process all the stringField values.
    for field in stringFields.keys():
        #Get and sanitise input
        searchString = str(request.form.get(field+"_searchString",""))
        if not sanitised(searchString):
            return (False,"Invalid Input for field: "+field+".", [])        
        stringFields[field]=searchString
        if len(searchString) > 0:
            filterFields.append(field)
            
            if field == 'cve':         
                field = "cves__id"
   
            lookup = stringQuery(field,searchString,lookup)
        
    #process all the hash keys
    for field in hashFields.keys():
        #Get and sanitise input
        searchString = str(request.form.get(field+"_searchString",""))
        if not sanitised(searchString):
            return (False,"Invalid Input for field: "+field+".", [])        
        hashFields[field]=searchString
        SetHashCheckedBoxes(field)        
        if len(searchString) > 0:            
            #if all is selected, then don't need to only look at combined
            #otherwise we filter by combined as well.
            if (hashCheckBoxes[field][1]):
                searchField = "hashes__%s" % field            
                lookup = stringQuery(searchField,searchString,lookup)            
                filterField = "hashes.%s.*" % field
                filterFields.append(filterField)
            elif (hashCheckBoxes[field][0]):
                searchField = "hashes__%s__combined" % field            
                lookup = stringQuery(searchField,searchString,lookup)            
                filterField = "hashes.%s.combined" % field
                filterFields.append(filterField)
                
    #process datefield
    day=request.form.get('date_day',"2013")
    month=request.form.get('date_month',"1")
    year=request.form.get('date_year',"1")
    option=request.form.get('date_option','any')
    dateFields['date_day_val']=day
    dateFields['date_month_val']=month
    dateFields['date_year_val']=year
    
    if len(day) > 0 and len(month)> 0 and len(year)>0:
        date = datetime.datetime(int(year),int(month),int(day))
        if option =='on':
            dateLookup = Q(submittedon=date)
        elif option =='before':
            dateLookup = Q(submittedon__lte=date)
        elif option =='after':
            dateLookup = Q(submittedon__gte=date)
        else:
            dateLookup = Q()
        
        lookup = lookup  & dateLookup
    
    
    
    
    if len(filterFields) == 0:
        #Nothing to search.
        return (False, "",[])
    
    #Do the actual search
    hashes = Hash.objects.only(*filterFields).only(*printFields).filter(lookup)
        
    if (len(hashes) == 0):
        return (False,"No Results Found",[])
    else:
        return (True,str(len(hashes)) + " Results Found",hashes)
 
    
    
    
def searchPOST(query=None):
    """This function handles the search once some part of the form has been submitted"""
    searchField = request.form.get('field','name')
    searchString = request.form.get('searchString','')   
    message="No Results Found"
    success=False
    
    if 'advSearch' in request.form:
        advanced="block"
        
        hashes = []
        success,message,hashes = advancedSearch()
    else:
        advanced="none"
        success,message,hashes = basicSearch(searchField,searchString)
    
   
    data={
        'advanced':advanced,
        'hashes':hashes,
        'success':success,
        'message':message,
        'basicString':searchString,
        'orderedStringFields':getOrderedStringFields(searchField),
        'stringFields':stringFields,
        'hashFields':hashFields,
        'checkFields':checkFields,
        'dateSearchValues':dateFields,
        'hashCheckBoxes':hashCheckBoxes
    }    
    return render_template('search.html', **data)

def searchGET(query=None):
    """This function handles the display of /search.html when no search query
    has been submitted. (i.e. the default view)"""
    #Reset Fields
    for dict in ['stringFields','hashFields','dateFields']:
        for key in eval(dict).keys():
            eval(dict)[key] = ""
    
    for group in checkFields.keys():
        for key in checkFields[group].keys():
            checkFields[group][key]=False

    for hashType in hashFields.keys():
        hashCheckBoxes[hashType]=[True,False]

    
    data={
        'hashes':[],
        'success':False,
        'message':"", 
        'basicString':"",
        'orderedStringFields':getOrderedStringFields(),
        'advanced':"none",
        'stringFields':stringFields,
        'hashFields':hashFields,
        'checkFields':checkFields,
        'dateSearchValues':dateFields,
        'hashCheckBoxes':hashCheckBoxes
        
    }
    return render_template('search.html', **data)
    
@dbSearch.route('/search', methods=['GET','POST'])
def search(query=None):
    """This function is highly coupled with search.html.
    The data keys that search.html look for are:
       
     Basic Search::
        basicString:  <string>: previous search string.
        orderedStringFields: [<string>]: list of fields that can be searched as string.
                            Ordered in alphabetical order, with previous selection as first.
                            

     Advanced Search::
       advanced: ["none"|"block"]: whether or not advanced search is used.
       date_day_val:: search value for submitted day
       date_month_val:: search value for submitted month
       date_year_val:: search value for submitted year

     Results::
        message: <string>: [#results found | error:...| No results found]
        success: <bool>: Whether the search succeeded (and returned some results)
        hashes: <[objects]>: Hash results from searching.
    
    """
    if request.method == 'POST':
        return searchPOST()
    else:
        return searchGET()
        
    
    