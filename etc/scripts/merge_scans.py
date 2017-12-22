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

from collections import OrderedDict
import json
import os

import click

from commoncode.fileutils import file_base_name


def merge_scans(scan_files):
    # FIXME: Figure out something to handle each input scan's scan notice,
    # version, and options
    merged_scan = OrderedDict()
    merged_scan['files_count'] = 0
    merged_scan['files'] = []

    for scan_file in scan_files:
        scan_file = os.path.abspath(os.path.expanduser(scan_file))
        with open(scan_file) as f:
            scan_results = json.loads(f.read(), object_pairs_hook=OrderedDict)

        merged_scan['files_count'] += scan_results['files_count']

        for result in scan_results['files']:
            path_prefix = file_base_name(scan_file)
            result['path'] = os.path.join(path_prefix, result['path'])
            merged_scan['files'].append(result)

    return merged_scan


@click.command()
@click.argument('scan_files', type=click.Path(exists=True, readable=True), nargs=-1)
@click.argument('output', type=click.File('wb', lazy=False), nargs=1)
@click.help_option('-h', '--help')
def cli(scan_files, output):
    merged_scans = merge_scans(scan_files)
    output.write(json.dumps(merged_scans))


if __name__ == '__main__':
    cli()
