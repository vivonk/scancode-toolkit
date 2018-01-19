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

from commoncode.fileutils import parent_directory
from hashlib import sha1
from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl
from scancode import CommandLineOption
from scancode import POST_SCAN_GROUP


@post_scan_impl
class MerkleTree(PostScanPlugin):
    """
    Compute the SHA1 hash for each directory from the hash of the directories and files within it
    """

    needs_info = True

    options = [
        CommandLineOption(('--merkle-tree',),
            is_flag=True,default=False,
            help='Compute the SHA1 hash for each directory from the hash of the directories and files within it',
            help_group=POST_SCAN_GROUP)
    ]

    def is_enabled(self):
        return self.is_command_option_enabled('merkle_tree')

    def process_codebase(self, codebase):
        dir_hashes = {}

        for resource in codebase.walk(topdown=False, sort=True):
            resource_path = resource.get_path()
            resource_parent_path = parent_directory(resource_path).strip('/')

            if not resource.is_file:
                resource.sha1 = dir_hashes[resource_path].hexdigest()
            if resource_parent_path in dir_hashes:
                dir_hashes[resource_parent_path].update(resource.sha1)
            else:
                dir_hashes[resource_parent_path] = sha1(resource.sha1)
