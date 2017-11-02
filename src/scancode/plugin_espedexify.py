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

import logging
import os
import sys

from plugincode.post_scan import post_scan_impl
from commoncode.fileutils import copyfile
from commoncode.fileutils import get_temp_dir


TRACE = True

logger = logging.getLogger(__name__)

def logger_debug(*args):
    pass

if TRACE:
    logging.basicConfig(stream=sys.stdout)
    logger.setLevel(logging.DEBUG)

    def logger_debug(*args):
        return logger.debug(' '.join(isinstance(a, basestring) and a or repr(a) for a in args))


"""
A post scan plugin to remove license boilerplate and replace this with
SPDX license idedntifiers
"""


@post_scan_impl
def replace_boilerplate_with_spdx_ids(active_scans, results):
    """
    WARNING: THIS PLUGIN DOES MODIFY THE SCANNED CODE
    Remove license boilerplate text from scanned files and replace
    it with a SPDX-License-Identifer.

    The logic for skipping a file is this:
     - not source code.
     - dooes not have a 100% score and 100% coverage detected license using a single rule.
     - does not have a detected license composed only of official SPDX license ids.

    The logic to modify a file is this:
     - determine the comment style of the detected license text lines.
     - remove the detected license text lines from the source file.
     - add a SPDX-License-Identifer with the correct expression using the comment style.

    Has no effect unless all these scan options are requested:
     `--license --info --diag --license-text --full-root`
    """

    # FIXME: this is forcing all the scan results to be loaded in memory
    # and defeats lazy loading from cache
    results = list(results)

    # FIXME: we should test for active scans instead, but "info" may not
    # be present for now. check if the first item has a file info.
    has_file_info = 'type' in results[0]

    # FIXME: we should test for active scans instead, but "info" may not
    # be present for now. check if the first item has a file info.
    has_licenses = 'licenses' in results[0]

    if not has_file_info or not has_licenses:
        # just yield results untouched
        for scanned_file in results:
            yield scanned_file
        return

    for scanned_file in results:

        if not (scanned_file['type'] == 'file' and scanned_file['is_source']):
            yield scanned_file

        scanned_location = scanned_file['path']
        assert os.path.exists(scanned_location)

        licenses = scanned_file['licenses']
        if not licenses:
            yield scanned_file

        # skip if we have more than one matched block
        matched_line_blocks = set((lic['start_line'], lic['end_line'],) for lic in licenses)
        if len(matched_line_blocks) != 1:
            yield scanned_file

        # skip if we have more than one matched rule
        matched_rules = set(lic['matched_rule']['identifier'] for lic in licenses)
        if len(matched_rules) != 1:
            yield scanned_file

        # skip if we have non SPDX official Ids
        is_official_spdx = all(lic['spdx_license_key'] for lic in licenses)
        if not is_official_spdx:
            yield scanned_file

        # from now on, we may have multiple records, but we have only one matched rule
        base_match = licenses[0]
        matched_rule = base_match['matched_rule']
        start_line = base_match['start_line']
        end_line = base_match['end_line']

        # skip if not 100% score and coverage
        if base_match['score'] != 100 or matched_rule['match_coverage'] != 100:
            yield scanned_file

        removed = remove_license_text(scanned_location, start_line, end_line)
        if TRACE: logger_debug('Removed license text from:', scanned_location, '\n', removed)
        spdx_id = build_spdx_id(matched_rule)

        matched_text = None
        comment_style = determine_comment_style(scanned_location, start_line, end_line, matched_text)
        added = add_spdx_id(scanned_location, spdx_id, start_line, comment_style)

        if TRACE: logger_debug('Added SPDX license id to:', scanned_location, '\n', added)

        yield scanned_file


def build_spdx_id(rule):
    """
    Return a SPDX-License-Identifier string build from a rule mapping.
    """
    keys = rule['licenses']
    choice = rule['license_choice']
    operator = ' OR ' if choice else ' AND '
    expression = operator.join(keys)
    multi = len(keys) > 1
    if multi:
        expression = '({})'.format(expression)
    return 'SPDX-License-Identifier: {}'.format(expression)


def determine_comment_style(location, start_line, end_line, matched_text):
    """
    Return a tuple of strings for the comment style as the start and
    end markers. The end marker may be an empty string.
    Return None if the match is not in a comment (such as in a literal).
    """
    # TODO implment me
    return '//', ''


def remove_license_text(location, start_line, end_line):
    """
    Remove matched license text from the file at `location`.
    Return the removed text as a string.
    WARNING: this modifies the file
    """
    tmp_dir = get_temp_dir(base_dir='spdx_id')
    new_file = os.path.join(tmp_dir, 'new_file')

    removed = ''
    with open(new_file, 'wb') as outputf:
        with open(location, 'rb') as inputf:
            for ln, line in enumerate(inputf, 1):
                if ln >= start_line and ln <= end_line:
                    removed += line
                    continue

                outputf.write(line)
    copyfile(new_file, location)
    return removed


def add_spdx_id(location, spdx_id, start_line, comment_style):
    """
    Add the spdx_id to the file at `location` at `start_line` using the `comment_style` tuple.
    Return the added text line as a string.
    WARNING: this modifies the file
    """
    startc, endc = comment_style
    identifier = startc + ' ' + spdx_id
    if endc:
        identifier += ' ' + endc

    tmp_dir = get_temp_dir(base_dir='spdx_id')
    new_file = os.path.join(tmp_dir, 'new_file')

    with open(new_file, 'wb') as outputf:
        with open(location, 'rb') as inputf:
            for ln, line in enumerate(inputf):
                if ln == start_line:
                    outputf.write(identifier)
                outputf.write(line)
    copyfile(new_file, location)
    return identifier
