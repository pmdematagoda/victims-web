# Copyright 2013

# Pramod Dematagoda <pmd.lotr.gandalf@gmail.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import urllib2
from datetime import datetime

from victims_web.models import Cache, Plugin
from victims_web.plugin.downloader import download

import xml.parsers.expat

# NIST v2 database files
_cve_sources_full = [
	"https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2002.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2003.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2004.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2005.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2006.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2007.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2008.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2009.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2010.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2011.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2012.xml",
        "https://nvd.nist.gov/static/feeds/xml/cve/nvdcve-2.0-2013.xml"
]

MTIME_FMT = "%j:%Y:%H:%M:%S"
CTIME_FMT = "%d:%m:%Y"
# The seconds in a day
DAY_SECONDS = 86400

class NIST_v2(object):
	# The current CVE ID/s being parsed
	_cve = ""

	'''
	Is the entry currently being processed something we want?
	A global because the value's needed by two functions.
	'''
	_valid = False

    	# The dictionary of valid vulnerable entries currently parsed
	_vuln_list = {}

    def __init__(self):

		if !_check_mtime_within():
	        for src in _cve_sources_full:
    	        source = _get_source(src)
    	        if source is None:
    	            continue
    	        else:
    	            _parse_nvd_file(source)

    def get_entries (self, name, version=None):
        """
        Function parses and aggregates _all_ vulnerability
        information from the predefind sources.

        Outputs :
        Returns a dictionary of the following format:
        dict[package_name] - returns a dictionary(dict2) of the format
        dict2[version] - list of CVEs affecting the given version
        dict2[vendor] - returns the vendor for the given package_name.
        """
        if version:
            return 

    def _parse_helper_nvd (self, name, attr):
        """
        Helper function that checks if data currently being processed
        is what we're looking for, if it is then the data is added
        to the global dictionary.

        Inputs :
        name - name of the tag being parsed.
        attr - the contents of the tag being parsed.
        """

        if name == "entry":
            self._cve = attr["id"]

        if name == "vuln:product":
            self._valid = True
        else:
            self._valid = False

    def _validate_data (entry):
        """
        Function to parse a given line of data from
        the nvd file to grab the information we need.

        Inputs :
        entry - the line of data where the victim data
        is stripped from.
        """

        cve_package = ""
        cve_package_version = ""
        vendor = ""

        '''
        It seems like the data we would need is contained
        after the 2nd element in the list, this may
        need further verification(verified). The format seems to be
        "cpe:\a:<vendor>:<name>:version-info(following)".
        '''
        conf_list = entry.split (":")
        if len (conf_list) >= 4:
            vendor = conf_list[2]
            cve_package = conf_list[3]
            for elem in conf_list[4:]:
                # Append all the version information together
                cve_package_version = cve_package_version + elem

        '''
        Do not encode the strings in unicode,
        it screws things up when using them.
        '''
        return (cve_package.encode ('ascii'),
                cve_package_version.encode ('ascii'),
                vendor.encode ('ascii'),
                cve.encode ('ascii'))


    def _parse_data_nvd (self, data):
        """
        Function that determines if the data parsed by the
        XML parser is what we need, if so
        it is added to the vulnerabilities dictionary.

        Inputs :
        data - a line of data in database file being parsed.
        """

        if self._valid:
            cve_entry = _validate_data (data)

            if len (cve_entry[0]) and len (cve_entry[1]):

                '''
                If the dictionary already contains a list for the given
                package name, just append the new cve entry to the list.
                '''
                if cve_entry[0] in self._vuln_list:
                    if cve_entry[1] in self._vuln_list[cve_entry[0]]:
                        self._vuln_list[cve_entry[0]][cve_entry[1]].append (cve_entry[3])
                    else:
                        self._vuln_list[cve_entry[0]][cve_entry[1]] = [cve_entry[3]]

                else:
                    '''
                    Create a new list for the package name
                    if a list does not exist.
                    '''
                    self._vuln_list[cve_entry[0]] = {}
                    self._vuln_list[cve_entry[0]]["vendor"] = cve_entry[2]
                    self._vuln_list[cve_entry[0]][cve_entry[1]] = [cve_entry[3]]

            self._valid = False


    def _parse_nvd_file (self, input_file):
        """
        Function to parse the data in the nvd file to find the
        appropriate cve entries and the program name and version.

        Inputs :
        input_file - File object to be parsed.
        """
        nvd_parser = xml.parsers.expat.ParserCreate ()
        nvd_parser.StartElementHandler = self._parse_helper_nvd
        nvd_parser.CharacterDataHandler = self._parse_data_nvd
        nvd_parser.ParseFile (input_file)

    def _add_mtime_stamp ():
        """
        Add a modificiation time stamp to the database.
        """
        mtimestr = datetime.strftime(datetime.utcnow(), MTIME_FMT)
		Plugin.set('nist_mtime', mtimestr)
	
	def _check_mtime_within (d_seconds=DAY_SECONDS):
        """
        Check if the cache is up to date.

        Inputs :
        d_seconds - the delta to check for in seconds

        Outputs :
        Returns True on mtime stamp within d_seconds
        Returns False on mtime stamp outside d_seconds
        """

		mtimestr = Plugin.get('nist_mtime')
		if mtimestr:
        	mtime = datetime.strptime (mtimestr, MTIME_FMT)

        	if mtime >= (datetime.utcnow () - timedelta (seconds=d_seconds)):
				return True

        return False 
