# Copyright 2024 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
Various utilities LUKS encryption related utilities.

"""

import logging

from oslo_utils import excutils

from ironic_python_agent import utils

LOG = logging.getLogger(__name__)


def check_luks_compatibility():
    """Checks whether the luks requirements are present

    """
    return True


def luks_re_encrypt_partition(key_file, partition, persistentFlags=[]):
    """Re-encrypt block deive with TPM credential

    :param key_file: plaintext version of the key file
    :param device: the device path of the block device that will be
    :param persistentFlags: cryptsetup flags to use when opening device
    encrypted
    """
    try:
        LOG.debug("Encrypting partition %s", partition)
        utils.execute('cryptsetup', 'reencrypt', '--encrypt', '--type',
                      'luks2', '--reduce-device-size', '32M', '--key-file',
                      key_file, partition)
        utils.execute('cryptsetup', 'luksAddKey', '--type', 'luks2',
                      '--key-file', key_file, partition, key_file)
        # If user has specified certain flags they want to use when opening
        # the partition, add those as persistent flags to the LUKS header.
        if len(persistentFlags) > 0:
            LOG.debug("Adding opening flags to LUKS headers: %s",
                      persistentFlags)
            if '--persistent' not in persistentFlags:
                persistentFlags.append('--persistent')
            luks_open_partition(key_file, partition, 'tmp_luks_open',
                                persistentFlags)
            luks_close_partition('tmp_luks_open')
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Re-encryption has failed for %(partition)s",
                      {'partition': partition})


def luks_open_partition(key_file, partition, map_target, flags=[]):
    """Unlock a LUKS encrypted block device

    :param key_file: plaintext version of the key file
    :param device: the device path of the block device that will be
    :param flags: cryptsetup flags to use when opening device
    encrypted
    """
    try:
        utils.execute('cryptsetup', 'open', '--type', 'luks2', '--key-file',
                      key_file, *flags, partition, map_target)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Failed to open encrypted device %(partition)s", {
                      'partition': partition})
    return '/dev/mapper/' + map_target


def luks_close_partition(map_target):
    try:
        utils.execute('cryptsetup', 'close', map_target)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Failed to close encrypted device %(target)",
                      {'target': map_target})
