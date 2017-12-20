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

from commoncode.fileutils import file_base_name
from commoncode.fileutils import file_name
from commoncode.fileutils import parent_directory
from hashlib import sha1
from plugincode.post_scan import post_scan_impl
from scancode.api import _empty_file_infos


class File(object):
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        string_repr = '{}(\'{}\')'.format(type(self).__name__, self.data['path'])
        return repr(string_repr)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data['path'] == other.data['path']
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Dir(object):
    def __init__(self, data):
        self.data = data
        self.dirs = []
        self.files = []

    def __repr__(self):
        string_repr = '{}(\'{}\')'.format(type(self).__name__, self.data['path'])
        return repr(string_repr)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data['path'] == other.data['path']
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def postorder_walk(self):
        for d in self.dirs:
            for subdir in d.postorder_walk():
                yield subdir
        yield self, self.dirs, self.files

    def as_tree(self, prefix=''):
        for f in self.files:
            print(prefix, f.data['name'])
        for d in self.dirs:
            print(prefix, d.data['name'])
            d.as_tree(prefix + '  ')


def build_tree(results):
    """
    Return a Dir tree object computed from a list of results
    """
    results = list(results)

    sample_file = results[0]
    sample_file_path = sample_file['path']
    root_path = sample_file_path.split('/')[0]

    root_data = _empty_file_infos()
    root_data['path'] = root_path
    root_data['basename'] = root_path
    root_data['name'] = root_path
    root_data['type'] = 'directory'

    root = Dir(root_data)
    dirs = {root_path: root}

    for scanned_file in results:
        path = scanned_file['path']
        isdir = scanned_file['type'] == 'directory'

        parent_path = parent_directory(path).strip('/')
        parent = dirs.get(parent_path)

        if not parent:
            parent_data = _empty_file_infos()
            parent_data['path'] = parent_path
            parent_data['basename'] = file_base_name(parent_path)
            parent_data['name'] = file_name(parent_path)
            parent_data['type'] = 'directory'
            parent = Dir(parent_data)
            dirs[parent_path] = parent

            # FIXME: we need to check to see if the parent of the new parent directory
            # we created exists and to attach them together until we reach the root
            #
            # There probably is a better way to do this
            current = parent
            while current != root:
                curr_path = current.data.get('path')
                curr_parent_path = parent_directory(curr_path).strip('/')
                curr_parent = dirs.get(curr_parent_path)
                if curr_parent:
                    for dir in curr_parent.dirs:
                        if dir.data['path'] == current.data['path']:
                            dir.dirs = current.dirs
                            dir.files = current.files
                            break
                    else:
                        curr_parent.dirs.append(current)
                else:
                    parent_data = _empty_file_infos()
                    parent_data['path'] = curr_parent_path
                    parent_data['basename'] = file_base_name(curr_parent_path)
                    parent_data['name'] = file_name(curr_parent_path)
                    parent_data['type'] = 'directory'
                    parent = Dir(parent_data)
                    dirs[curr_parent_path] = parent
                    curr_parent = parent
                current = curr_parent

        if isdir:
            d = Dir(scanned_file)
            parent.dirs.append(d)
        else:
            f = File(scanned_file)
            parent.files.append(f)

    return root


@post_scan_impl
def build_merkle_tree(active_scans, results):
    """
    Calculate hash of hashes in directories
    """

    # FIXME: this is forcing all the scan results to be loaded in memory
    # and defeats lazy loading from cache
    results = list(results)

    root = build_tree(results)
    hash_stack = []

    for present_dir, dirs, files in root.postorder_walk():
        dir_hash = sha1()

        # We add the SHA1 of the files of a directory to the directory hash
        for file in files:
            dir_hash.update(file.data['sha1'])
            yield file.data

        if dirs:
            # If the directory we are in has directories, we iterate through the
            # `hash_stack` list of all the hashes of the directories we previously
            # processed and add their hex digest values to the current directory hash
            #
            # By walking the tree in a postorder fashion, we visit and process
            # the files and directories within a directory before the directory itself
            for hash in hash_stack:
                dir_hash.update(hash.hexdigest())
            # We no longer need to keep the hashes around because we processed
            # all of them for this directory
            hash_stack = []
        else:
            # We keep this directory's hash around until we process the parent
            # of the directory we are in
            hash_stack.append(dir_hash)

        present_dir.data['sha1'] = dir_hash.hexdigest()
        yield present_dir.data
