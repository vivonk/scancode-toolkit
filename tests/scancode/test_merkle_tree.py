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
from __future__ import unicode_literals

import json
import os

from commoncode.testcase import FileBasedTesting
from scancode.api import _empty_file_infos
from scancode.plugin_merkle_tree import Dir
from scancode.plugin_merkle_tree import File
from scancode.plugin_merkle_tree import build_tree
from scancode.plugin_merkle_tree import build_merkle_tree


class TestMerkleTree(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data')

    def test_merkle_tree_postorder_walk(self):
        test_file = self.get_test_loc('merkle_tree/sample.json')
        scan_results = json.loads(open(test_file).read())['files']
        root = build_tree(scan_results)

        expected_results = [
            ('u"Dir(\'samples/zlib/dotzlib\')"', '[]', '[u"File(\'samples/zlib/dotzlib/ChecksumImpl.cs\')", u"File(\'samples/zlib/dotzlib/LICENSE_1_0.txt\')", u"File(\'samples/zlib/dotzlib/AssemblyInfo.cs\')", u"File(\'samples/zlib/dotzlib/readme.txt\')"]'),
            ('u"Dir(\'samples/zlib/ada\')"', '[]', '[u"File(\'samples/zlib/ada/zlib.ads\')"]'),
            ('u"Dir(\'samples/zlib/gcc_gvmat64\')"', '[]', '[u"File(\'samples/zlib/gcc_gvmat64/gvmat64.S\')"]'),
            ('u"Dir(\'samples/zlib/infback9\')"', '[]', '[u"File(\'samples/zlib/infback9/infback9.h\')", u"File(\'samples/zlib/infback9/infback9.c\')"]'),
            ('u"Dir(\'samples/zlib/iostream2\')"', '[]', '[u"File(\'samples/zlib/iostream2/zstream_test.cpp\')", u"File(\'samples/zlib/iostream2/zstream.h\')"]'),
            ('u"Dir(\'samples/zlib\')"', '[u"Dir(\'samples/zlib/dotzlib\')", u"Dir(\'samples/zlib/ada\')", u"Dir(\'samples/zlib/gcc_gvmat64\')", u"Dir(\'samples/zlib/infback9\')", u"Dir(\'samples/zlib/iostream2\')"]', '[u"File(\'samples/zlib/zutil.h\')", u"File(\'samples/zlib/zutil.c\')", u"File(\'samples/zlib/deflate.c\')", u"File(\'samples/zlib/deflate.h\')", u"File(\'samples/zlib/adler32.c\')", u"File(\'samples/zlib/zlib.h\')"]'),
            ('u"Dir(\'samples/JGroups/licenses\')"', '[]', '[u"File(\'samples/JGroups/licenses/apache-2.0.txt\')", u"File(\'samples/JGroups/licenses/cpl-1.0.txt\')", u"File(\'samples/JGroups/licenses/lgpl.txt\')", u"File(\'samples/JGroups/licenses/bouncycastle.txt\')", u"File(\'samples/JGroups/licenses/apache-1.1.txt\')"]'),
            ('u"Dir(\'samples/JGroups/src\')"', '[]', '[u"File(\'samples/JGroups/src/ImmutableReference.java\')", u"File(\'samples/JGroups/src/RouterStubManager.java\')", u"File(\'samples/JGroups/src/GuardedBy.java\')", u"File(\'samples/JGroups/src/S3_PING.java\')", u"File(\'samples/JGroups/src/RouterStub.java\')", u"File(\'samples/JGroups/src/RATE_LIMITER.java\')", u"File(\'samples/JGroups/src/FixedMembershipToken.java\')"]'),
            ('u"Dir(\'samples/JGroups\')"', '[u"Dir(\'samples/JGroups/licenses\')", u"Dir(\'samples/JGroups/src\')"]', '[u"File(\'samples/JGroups/EULA\')", u"File(\'samples/JGroups/LICENSE\')"]'), ('u"Dir(\'samples/arch\')"', '[]', '[u"File(\'samples/arch/zlib.tar.gz\')"]'), ('u"Dir(\'samples\')"', '[u"Dir(\'samples/zlib\')", u"Dir(\'samples/JGroups\')", u"Dir(\'samples/arch\')"]', '[u"File(\'samples/screenshot.png\')", u"File(\'samples/README\')"]')
        ]

        results = list(('{}'.format(current_dir), '{}'.format(dirs), '{}'.format(files)) for current_dir, dirs, files in root.postorder_walk())

        assert expected_results == results

    def test_merkle_tree_build_tree(self):
        test_file = self.get_test_loc('merkle_tree/build_tree.json')
        scan_results = json.loads(open(test_file).read())['files']
        results = build_tree(scan_results)

        dir_1 = {
            'path': 'JGroups/licenses',
            'type': 'directory',
            'name': 'licenses',
            'base_name': 'licenses',
            'extension': '',
            'date': None,
            'size': 54552,
            'sha1': None,
            'md5': None,
            'files_count': 5,
            'mime_type': None,
            'file_type': None,
            'programming_language': None,
            'is_binary': False,
            'is_text': False,
            'is_archive': False,
            'is_media': False,
            'is_source': False,
            'is_script': False,
            'scan_errors': []
        }

        dir_2 = {
            'path': 'JGroups/src',
            'type': 'directory',
            'name': 'src',
            'base_name': 'src',
            'extension': '',
            'date': None,
            'size': 152090,
            'sha1': None,
            'md5': None,
            'files_count': 7,
            'mime_type': None,
            'file_type': None,
            'programming_language': None,
            'is_binary': False,
            'is_text': False,
            'is_archive': False,
            'is_media': False,
            'is_source': False,
            'is_script': False,
            'scan_errors': []
        }

        file_1 = {
            'path': 'JGroups/LICENSE',
            'type': 'file',
            'name': 'LICENSE',
            'base_name': 'LICENSE',
            'extension': '',
            'date': '2017-07-11',
            'size': 26430,
            'sha1': 'e60c2e780886f95df9c9ee36992b8edabec00bcc',
            'md5': '7fbc338309ac38fefcd64b04bb903e34',
            'files_count': None,
            'mime_type': 'text/plain',
            'file_type': 'ASCII text',
            'programming_language': None,
            'is_binary': False,
            'is_text': True,
            'is_archive': False,
            'is_media': False,
            'is_source': False,
            'is_script': False,
            'scan_errors': []
        }

        file_2 = {
            'path': 'JGroups/licenses/apache-2.0.txt',
            'type': 'file',
            'name': 'apache-2.0.txt',
            'base_name': 'apache-2.0',
            'extension': '.txt',
            'date': '2017-07-11',
            'size': 11560,
            'sha1': '47b573e3824cd5e02a1a3ae99e2735b49e0256e4',
            'md5': 'd273d63619c9aeaf15cdaf76422c4f87',
            'files_count': None,
            'mime_type': 'text/plain',
            'file_type': 'ASCII text, with CRLF line terminators',
            'programming_language': None,
            'is_binary': False,
            'is_text': True,
            'is_archive': False,
            'is_media': False,
            'is_source': False,
            'is_script': False,
            'scan_errors': []
        }

        file_3 = {
            'path': 'JGroups/src/ImmutableReference.java',
            'type': 'file',
            'name': 'ImmutableReference.java',
            'base_name': 'ImmutableReference',
            'extension': '.java',
            'date': '2017-07-11',
            'size': 1838,
            'sha1': '30f56b876d5576d9869e2c5c509b08db57110592',
            'md5': '48ca3c72fb9a65c771a321222f118b88',
            'files_count': None,
            'mime_type': 'text/plain',
            'file_type': 'ASCII text',
            'programming_language': 'Java',
            'is_binary': False,
            'is_text': True,
            'is_archive': False,
            'is_media': False,
            'is_source': True,
            'is_script': False,
            'scan_errors': []
        }

        expected_root_data = _empty_file_infos()
        expected_root_data['path'] = 'JGroups'
        expected_root_data['basename'] = 'JGroups'
        expected_root_data['name'] = 'JGroups'
        expected_root_data['type'] = 'directory'

        expected_results = Dir(expected_root_data)
        expected_results.dirs.append(Dir(dir_1))
        expected_results.dirs.append(Dir(dir_2))
        expected_results.files.append(File(file_1))
        expected_results.dirs[0].files.append(File(file_2))
        expected_results.dirs[1].files.append(File(file_3))

        assert expected_results == results

    def test_merkle_tree_as_tree(self):
        import cStringIO
        import sys
        import textwrap

        test_file = self.get_test_loc('merkle_tree/sample.json')
        scan_results = json.loads(open(test_file).read())['files']
        root = build_tree(scan_results)

        expected_results = '''\
            screenshot.png
            README
            zlib
              zutil.h
              zutil.c
              deflate.c
              deflate.h
              adler32.c
              zlib.h
              dotzlib
                ChecksumImpl.cs
                LICENSE_1_0.txt
                AssemblyInfo.cs
                readme.txt
              ada
                zlib.ads
              gcc_gvmat64
                gvmat64.S
              infback9
                infback9.h
                infback9.c
              iostream2
                zstream_test.cpp
                zstream.h
            JGroups
              EULA
              LICENSE
              licenses
                apache-2.0.txt
                cpl-1.0.txt
                lgpl.txt
                bouncycastle.txt
                apache-1.1.txt
              src
                ImmutableReference.java
                RouterStubManager.java
                GuardedBy.java
                S3_PING.java
                RouterStub.java
                RATE_LIMITER.java
                FixedMembershipToken.java
            arch
              zlib.tar.gz
        '''
        # Remove leading spaces on every line
        expected_results = textwrap.dedent(expected_results)

        # We redirect the print calls from as_tree() into a buffer,
        # then we compare the buffer against `expected_results`
        # From https://stackoverflow.com/a/22823751
        stdout_ = sys.stdout  # Keep track of the previous value.
        stream = cStringIO.StringIO()
        sys.stdout = stream

        # as_tree will then print out every file and directory within the
        # directory it visits into `stream`
        root.as_tree()

        sys.stdout = stdout_  # restore the previous stdout.
        results = stream.getvalue()

        assert expected_results == results

    def test_merkle_tree_build_merkle_tree(self):
        test_file = self.get_test_loc('merkle_tree/build_tree.json')
        scan_results = json.loads(open(test_file).read())['files']
        active_scans = ['infos']
        results = list(build_merkle_tree(active_scans, scan_results))

        expected_results_file = self.get_test_loc('merkle_tree/build_merkle_tree.json')
        expected_results = json.loads(open(expected_results_file).read())['files']

        assert expected_results == results
