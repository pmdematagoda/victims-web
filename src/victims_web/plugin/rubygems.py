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
Provide support for downloading ruby gems using the rubygems
repository.
"""
from logging import getLogger
from os.path import join
from string import Template

from victims_web.plugin.downloader import download

logger = getLogger('plugin.rubygems')


class Gem(object):
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def to_rg_name(self, ext="gem"):
        return "%s-%s.%s" % (
            self.name, self.version, ext
        )

    def __eq__(self, other):
        if isinstance(other, Gem):
            return (
                other.name == self.name
                and other.version == self.version
            )
        else:
            return False

    def __str__(self):
        return "%s:%s" % (self.name, self.version)

    def __repr__(self):
        return self.__str__()


class RubyGems(object):
    def __init__(self, name, uri):
        self.name = name
        self.uri = uri

    def __eq__(self, other):
        if isinstance(other, RubyGems):
            return self.uri == other.uri
        else:
            return False

    def download_gem(self, gem, local_path,
                     prefix='victims.plugin.rubygems', async=True):
        """
        Function to download a requested gem from the connected
        repository.

        Inputs:

        gem - an object containing information relating to a specific gem.
        local_path - path for the gem to be downloaded to.
        prefix - prefix to be appended to the downloaded file.
        async - download the file asynchronously to victims-web process

        Output:

        Returns a string containing the local path to the downloaded gem.
        """
        rg_path = self.get_gem_uri(artifact, 'gem')
        logger.info('[Downloading] gem from %s' % rg_path)
        local_gem_path = join(
            local_path, '%s-%s' % (prefix, gem.to_rg_name())
        )
        local_f = open(local_gem_path, 'w')
        download(rg_path, local_f, async)
        logger.info('[Finished] %s downloaded ' % rg_path)
        return local_gem_path

    def get_gem_uri(self, gem, ext):
        """
        Get the URI for the gem to be downloaded on the ruby gems repo.

        Inputs:

        gem - object containing information about the gem.
        ext - extension of the gem.

        Outputs:

        Returns the link to the gem requested.
        """
        rg_name = gem.to_rg_name(ext)

        if self.uri.endswith('/'):
            rg_path = self.uri + rg_name
        else:
            rg_path = self.uri + '/' + rg_name

        return rg_path
