#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
from __future__ import unicode_literals

from os.path import dirname

from hashlib import sha1
from plugincode.post_scan import post_scan_impl


@post_scan_impl
def process_merkle_tree(active_scans, results):
    """
    Calculate hash of hashes in directories
    """

    # FIXME: this is forcing all the scan results to be loaded in memory
    # and defeats lazy loading from cache
    results = list(results)

    # We prep our data to be more condusive to bottom-up sorting with the files
    # of directories ordered before the directories
    bottom_up_results = []
    for scanned_file in results:
        bottom_up_results.append((-len(scanned_file['path'].split('/')), scanned_file['type'] == 'directory', scanned_file['path'].split('/'), scanned_file))
    bottom_up_results = sorted(bottom_up_results)

    dir_hash_store = {}
    for result_tuple in bottom_up_results:
        scanned_file = result_tuple[-1]
        scanned_file_path = scanned_file.get('path')

        if scanned_file['type'] == 'directory':
            # If a directory only has directories in it
            if scanned_file_path not in dir_hash_store:
                dir_hash = sha1()
                for k, v in dir_hash_store.iteritems():
                    if k.startswith(scanned_file_path):
                        dir_hash.update(v.hexdigest())
                dir_hash_store[scanned_file_path] = dir_hash
            # If there were files in a directory, we need to collect the
            # hashes of the directories in the directory
            else:
                for k, v in dir_hash_store.iteritems():
                    if k.startswith(scanned_file_path):
                        dir_hash_store[scanned_file_path].update(v.hexdigest())
            scanned_file.update({'sha1': dir_hash_store[scanned_file_path].hexdigest()})
        else:
            dirpath = dirname(scanned_file_path)
            scanned_file_sha1 = scanned_file.get('sha1')

            if dirpath in dir_hash_store:
                dir_hash_store[dirpath].update(scanned_file_sha1)
            else:
                dir_hash_store[dirpath] = sha1(scanned_file_sha1)

        yield scanned_file
