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
Provide support for downloading python packages using the pypi
repository and pip.
"""
from logging import getLogger
from os.path import join
from string import Template

from pip.index import PackageFinder
from pip.req import InstallRequirement

from victims_web.plugin.downloader import download, checksum

logger = getLogger('plugin.pypi')


class PyPi(object):
    def __init__(self, index_urls):
        self._index_urls = index_urls

    @property
    def index_urls(self):
        return self._index_urls

    @index_urls.setter
    def index_urls(self, index_urls):
        self._index_urls = index_urls
        self._update_finder()

    def _update_finder(self):
        self._finder = PackageFinder(find_links=[],
                                     index_urls=self._index_urls)

    def append_index_urls(self, index_urls):
        for url in index_urls:
            if url not in self._index_urls:
                self._index_urls.append(url)

        self._update_finder()

    def get_download_link(self, package, version):
        """
        Function that returns a Link object of the required package.
        It uses pip to construct a Requirement object which is used
        by the PackagerFinder inside the current PyPi object to
        generate a Link object pointing to the package.

        Inputs:

        package - name of package.
        version - version of package.

        Outputs:

        Returns a Link object pointing to the package requested.
        """
        requirement_string = '%s==%s' % (package, version)
        requirement = InstallRequirement.from_line(requirement_string, None)
        return self._finder.find_requirement(requirement)

    def download(self, package, version, local_path,
                 prefix='victims.plugin.pypi', verify=True, async=False):
        """
        Function to download a requested package from the connected
        repository.

        Inputs:

        package - package name of the python package.
        version - version of the python package.
        local_path - path for the package to be downloaded to.
        prefix - prefix to be appended to the downloaded file.
        verify - verify the downloaded package's checksum.
        async - download the file asynchronously to victims-web process.

        Output:

        Returns a string containing the local path to the downloaded package.
        """
        link = get_download_link(package, version)
        py_path = link.url_without_fragment

        logger.info('[Downloading] package from %s' % (py_path))
        local_package_path = join(
            local_path, '%s-%s' % (prefix, link.filename)
        )
        local_f = open(local_package_path, 'w')
        download(py_path, local_f, async)
        logger.info('[Finished] %s downloaded' % py_path)

        if verify and not async:
            logger.info('[Verification] %s' % py_path)
            f_checksum = checksum(py_path, link.hash_name)

            if f_checksum != link.hash:
                raise DownloadException(
                    py_path, 'Verification failed for downloaded package'
                )

        elif async:
            logger.warn('[Verification] skipped due to async download')

        return local_package_path
