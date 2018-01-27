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
from scancode import halohash


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
            if resource.children():
                sha1s = []
                bah128s = []
                for child in resource.children():
                    sha1 = child.sha1
                    if sha1:
                        sha1s.append(bytes(sha1))
                    m_sha1 = get_fingerprint_field(child, 'merkle_sha1')
                    if m_sha1:
                        sha1s.append(bytes(m_sha1))

                    bah128 = get_fingerprint_field(child, 'bah128')
                    if bah128:
                        bah128s.append(bytes(bah128))
                    m_bah128 = get_fingerprint_field(child, 'merkle_bah128')
                    if m_bah128:
                        bah128s.append(bytes(m_bah128))

                merkle_sha1 = hashlib.sha1(b''.join(sorted(sha1s))).hexdigest()
                set_fingerprint_field(resource, 'merkle_sha1', merkle_sha1)

                merkle_bah128 = halohash.BitAverageHaloHash(b''.join(sorted(bah128s))).hexdigest()
                set_fingerprint_field(resource, 'merkle_bah128', merkle_bah128)


def get_fingerprint_field(resource, field):
    scans = resource.get_scans()
    if not scans:
        return
    fingerprints = scans.get('fingerprints', [])
    if fingerprints:
        fingerprint = fingerprints[0]
        return fingerprint.get(field) or None


def set_fingerprint_field(resource, field, field_value):
    scans = resource.get_scans()
    fingerprints = scans.get('fingerprints', [])
    if fingerprints:
        fingerprint = fingerprints[0]
    else:
        fingerprint = OrderedDict()
        fingerprints.append(fingerprint)
    fingerprint[field] = field_value
    scans['fingerprints'] = fingerprints
    resource.put_scans(scans)
