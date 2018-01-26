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

import hashlib
from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl


@post_scan_impl
class MerkleTree(PostScanPlugin):
    """
    Compute the SHA1 hash for each directory from the hash of the directories and files within it
    """

    needs_info = True

    def is_enabled(self):
        return self.is_command_option_enabled('fingerprints')

    def process_codebase(self, codebase, **kwargs):
        """
        Compute a Merkle fingerprint using existing SHA1s by treating the codebase
        as a Merkle tree
        """

        # We walk bottom-up to ensure we process the children of directories
        # before we calculate and assign the Merkle fingerprint for directories
        for resource in codebase.walk(topdown=False):
            fingerprint = []

            # Collect the SHA1s of files and the previously computed Merkle SHA1's
            # of directories
            if resource.children():

                # Collect files SHA1s
                sha1s = [bytes(r.sha1) for r in resource.children() if r.sha1]
                for child in resource.children():
                    scans = child.get_scans()
                    if not scans:
                        continue
                    fingerprints = scans.get('fingerprints', {})
                    
                    ms = fingerprints.get('merkle_sha1', b'')
                    sha1s.append(bytes(ms))
                merkle = hashlib.sha1(b''.join(sorted(sha1s))).hexdigest()
                fingerprint['merkle_sha1'] = merkle
            scan = OrderedDict(fingerprints=fingerprint)
            resource.put_scans(scan)
