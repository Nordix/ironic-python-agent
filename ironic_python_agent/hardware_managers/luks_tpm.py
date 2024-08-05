# Copyright 2024 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re


# from ironic_python_agent import errors
from ironic_lib import exception
from ironic_lib import utils
from oslo_log import log
from oslo_utils import excutils

from ironic_python_agent import disk_utils
from ironic_python_agent import hardware
from ironic_python_agent.hardware_managers.luks import luks_utils as luks
from ironic_python_agent.hardware_managers.tpm import tpm_utils as tpm

LOG = log.getLogger()


def _detect_dependency():
    """detect whether the LUKS and TPM software and hardware is present

    :returns: Boolean value. True if the ramdisk and the machine is
    compatible with LUKS and TPM.
    """
    # TODO(adam) check growpart and lsblk
    luks_compatibility = luks.check_luks_compatibility
    tpm_conpatibility = tpm.check_tpm_compatibility
    return luks_compatibility and tpm_conpatibility


def _grow_part(partition_info):
    """Attempting to grow the partition with Canonical's growpart tool

    :param partition: path to the partition intended to be grown
    """
    try:
        # (adam) figure out the parent device of the partition to split the
        # device name and the partition suffix from each each outher, then
        # remove potential non digit content from the partition suffix to get
        # the partition index
        # (adam) I would preffer to move this into the generic disk or
        # partition ustils module
        # parent = utils.execute('lsblk', '-ndo', 'NAME', partition)[0]
        # part_suffix = re.sub(parent, '', partition)
        # part_num = re.sub('p', '', re.sub('-part', '', part_suffix))
        idx_num = partition_info['index_number']
        device = partition_info['device']
        sector_size = disk_utils.get_dev_sector_size(device)
        luks_header_sector_size = int(32 * 1024 * 1024 / sector_size)
        part_info = utils.execute('sgdisk', '-i', idx_num, device)[0]
        part_info_lines = part_info.splitlines()
        first_sector = re.split(" ", part_info_lines[2])[2]
        last_sector = re.split(" ", part_info_lines[3])[2]
        last_sector = str(int(last_sector) + luks_header_sector_size)
        utils.execute('sgdisk', '-e', '-d', idx_num, '-n',
                      str(idx_num) + ':' + str(first_sector) + ':'
                      + str(last_sector), device)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Can't grow %(partition)s, first sector:"
                      "%(first)s , last sector: %(last)",
                      {'partition': partition_info['partition_path'],
                       'first': first_sector, 'last': last_sector})


def _get_partition_parent_device_name(path_to_partition):
    """TODO"""
    parent_device = ""
    try:
        utils.execute('lsblk', '-no', 'PKNAME', path_to_partition)
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Can't determine the parent block device of"
                      "%(partition)s", {'partition': path_to_partition})
    return parent_device


def detect_root_partition_on_device(disk):
    """This return the device path of the root partition from a disk

    The detection of the root partition is done according to the
    Linux UAPI DPS. The first partition that has the
    4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709 type GUID (typecode) that represents
    an x86/amd64 linux root partition according to the Linux UAPI DPS.

    :param disk: device path of target disk
    :return: file system path of the root partition on the disk
    :rtype: string
    """
    partitions = disk_utils.list_partitions(disk)
    root_partition_info = None
    try:
        for part in partitions:
            p_num = part['number']
            lines = utils.execute('sgdisk', '--info', p_num, disk)[0]
            line = lines.splitlines()[0]
            typecode = re.split(" ", line)[3]
            if typecode == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709":
                partition_path = disk_utils.partition_index_to_path(disk,
                                                                    p_num)
                root_partition_info = {'partition_path': partition_path,
                                       'index_number': p_num}
        if not root_partition_info:
            error_msg = "ERROR: Can't find typecode match!"
            raise exception.InstanceDeployFailure(error_msg)
        utils.execute('ln', '-s', root_partition_info['partition_path'],
                      '/tmp/root_partition')
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.error("ERROR: Can't find root partition on %(device)s", {
                      'device': disk})
    return root_partition_info


class LuksTpmHardwareManager(hardware.HardwareManager):
    """Hardware manager for encrypting disk with LUKS and TPM"""

    HARDWARE_MANAGER_NAME = 'LuksTpmHardwareManager'
    HARDWARE_MANAGER_VERSION = '1'

    def evaluate_hardware_support(self):
        """Declare level of hardware support provided."""

        if _detect_dependency():
            LOG.debug('DEBUG: TPM+LUKS based encryption is supported!')
            # (adam) Not totally sure if this should be GENERIC or MAINLINE
            return hardware.HardwareSupport.MAINLINE
        else:
            LOG.debug('DEBUG: TPM+LUKS based encryption is not supported!')
            return hardware.HardwareSupport.NONE

    def whole_disk_image_encryption(self, device, *args, **kwargs):
        """(RE)Encrypts the root partition in the whole disk image workflow

        This function will re-encrypt the root partition (specified by
        Linux UAPI DPS) of the disk image after it was written to the disk.

        :param device: The device where the root partition is expected to
        reside
        """
        root_partition_info = detect_root_partition_on_device(device)
        root_partition_info['device'] = device
        _grow_part(root_partition_info)
        luks.luks_re_encrypt_partition(tpm.check_and_generate_key_file(),
                                       root_partition_info['partition_path'])

    def config_drive_encryption(self, conf_part, *args, **kwargs):
        """This is called in both whole disk and partition image workflows

        In both whole disk and partition image scenarios config drive
        partition is usually created by IPA based and populated with
        data recieved by IPA via it's API.

        This function is expected to be executed after the config drive
        partition is created but before it is populated with the data.

        :param config_part: device path to the config drive partition
        """
        luks.luks_re_encrypt_partition(tpm.check_and_generate_key_file(),
                                       conf_part)

    def config_drive_open(self, conf_part, *args, **kwargs):
        """Open the encrypted configdrive right after encryption

        :param config_part: the device path to the config drive partition
        :return: device path to the 'open' config drive partition
        :rtype: string
        """
        return luks.luks_open_partition(tpm.unseal_tpm_key(), conf_part,
                                        'config-2')

    def partition_image_root_partition_encryption(self, partition, *args,
                                                  **kwargs):
        """This is being called in the partition image workflow.

        In this hardware manager when this function is called it will
        LUKS+TPM to encrypt the already creaed but empty root partition.
        It is expected that that the path to the partition is known to IPA
        already because it has created the partition.

        :param partition: device path to the partition
        """
        LOG.error('ERROR: Partition image encryption is not yet implementd!')
        # TODO(adam) throw uncompatibility exception
        pass
        # _grow_part(root_partition)
        # luks.luks_encrypt_device(tpm.check_and_generate_key_file(),
        # partition)

    def partition_image_initrd_customization(self, partition, *args, **kwargs):
        """Customizes the already populated esp/boot partition

        It is expected that IPA might create a boot partition in during
        the partition image workflow. In case a boot partition was created
        the user has to provide a image for that partition. When the
        encryption is enabled IPA has to customize the mentioned boot
        partition as the initrd in the boot partition won't have prior
        knowledge about the encryption configuration.

        :param partition: The device patht to the partition
        """
        LOG.error('ERROR: Partition image encryption is not yet implementd!')
        # TODO(adam) throw uncompatibility exception
        pass

    def partition_image_open_root_partition(self, partition, *args, **kwargs):
        """Opens encrypted device and creates mountable device mapping

        Used after the root partition has been already encrypted in the
        partition image workflow.


        :param partition: encrypted partition
        :return: returns the mountable device path
        :rtype: string
        """
        LOG.error('ERROR: Partition image encryption is not yet implementd!')
        # TODO(adam) throw uncompatibility exception
        pass
