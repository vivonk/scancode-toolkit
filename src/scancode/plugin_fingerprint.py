#
# Copyright (c) 2018 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from collections import OrderedDict

from commoncode import filetype
from plugincode.scan import ScanPlugin
from plugincode.scan import scan_impl
from scancode import CommandLineOption
from scancode import SCAN_GROUP


@scan_impl
class FingerprintScanner(ScanPlugin):
    """
    Calculate the Halo Hash value of a Resource.
    """
    sort_order = 4

    options = [
        CommandLineOption(('-g', '--fingerprints',),
            is_flag=True, default=False,
            help='Calculate the Halo Hash value for <input>.',
            help_group=SCAN_GROUP)
    ]

    def is_enabled(self):
        return self.is_command_option_enabled('fingerprints')

    def get_scanner(self, **kwargs):
        return get_fingerprint


def get_fingerprint(location, **kwargs):
    """
    Return a list of mappings for copyright detected in the file at `location`.
    """
    from scancode.halohash import BitAverageHaloHash

    if not filetype.is_file(location):
        return []

    # fixme: we should read in chunks?
    with open(location, 'rb') as f:
        hashable = f.read()

    bah = BitAverageHaloHash(hashable)

    return [OrderedDict(bah128=[bah.hexdigest()])]
