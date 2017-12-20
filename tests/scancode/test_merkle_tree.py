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
from scancode.plugin_merkle_tree import build_tree


class TestMerkleTree(FileBasedTesting):
    test_data_dir = os.path.join(os.path.dirname(__file__), 'data')

    def test_merkle_tree_build_tree(self):
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
