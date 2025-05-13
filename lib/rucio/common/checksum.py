# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import io
import mmap
import zlib
from functools import partial
from typing import TYPE_CHECKING

from rucio.common.bittorrent import merkle_sha256
from rucio.common.exception import ChecksumCalculationError

if TYPE_CHECKING:
    from _typeshed import FileDescriptorOrPath

# GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5', 'sha256', 'crc32']
GLOBALLY_SUPPORTED_CHECKSUMS = ['adler32', 'md5']
PREFERRED_CHECKSUM = GLOBALLY_SUPPORTED_CHECKSUMS[0]
CHECKSUM_KEY = 'supported_checksums'


def is_checksum_valid(checksum_name: str) -> bool:
    """
    A simple function to check whether a checksum algorithm is supported.
    Relies on GLOBALLY_SUPPORTED_CHECKSUMS to allow for expandability.

    :param checksum_name: The name of the checksum to be verified.
    :returns: True if checksum_name is in GLOBALLY_SUPPORTED_CHECKSUMS list, False otherwise.
    """

    return checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS


def set_preferred_checksum(checksum_name: str) -> None:
    """
    If the input checksum name is valid,
    set it as PREFERRED_CHECKSUM.

    :param checksum_name: The name of the checksum to be verified.
    """
    if is_checksum_valid(checksum_name):
        global PREFERRED_CHECKSUM
        PREFERRED_CHECKSUM = checksum_name


def _iter_blocks(fobj):
    """Iterate over blocks in a binary file-like object.

    Uses blocks of size ``io.DEFAULT_BUFFER_SIZE * 8``.
    """
    block_size = io.DEFAULT_BUFFER_SIZE * 8
    return iter(partial(fobj.read, block_size), b'')


def adler32(file: "FileDescriptorOrPath") -> str:
    """
    Returns a standard CRC32 checksum compatible with XRootD (IEEE 802.3 polynomial).
    Output is an 8-character lowercase hex string.
    """
    crc = 0

    try:
        with open(file, 'rb') as f:
            for block in _iter_blocks(f):
                crc = zlib.crc32(block, crc)
    except Exception as e:
        raise ChecksumCalculationError('crc32', str(file), e)

    # Ensure result is in 32-bit unsigned form
    return format(crc & 0xFFFFFFFF, '08x')


def md5(file: "FileDescriptorOrPath") -> str:
    """
    Runs the MD5 algorithm (RFC-1321) on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file, "rb") as f:
            for block in _iter_blocks(f):
                hash_md5.update(block)
    except Exception as e:
        raise ChecksumCalculationError('md5', str(file), e)

    return hash_md5.hexdigest()


def sha256(file: "FileDescriptorOrPath") -> str:
    """
    Runs the SHA256 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    checksum = hashlib.sha256()
    try:
        with open(file, "rb") as f:
            for block in _iter_blocks(f):
                checksum.update(block)
    except Exception as e:
        raise ChecksumCalculationError('sha256', str(file), e)
    return checksum.hexdigest()


def crc32(file: "FileDescriptorOrPath") -> str:
    """
    Runs the CRC32 algorithm on the binary content of the file named file and returns the hexadecimal digest

    :param file: file name
    :returns: string of 32 hexadecimal digits
    """
    prev = 0
    try:
        with open(file, "rb") as f:
            for block in _iter_blocks(f):
                prev = zlib.crc32(block, prev)
    except Exception as e:
        raise ChecksumCalculationError('crc32', str(file), e)
    return "%X" % (prev & 0xFFFFFFFF)


CHECKSUM_ALGO_DICT = {
    'adler32': adler32,
    'md5': md5,
    'sha256': sha256,
    'crc32': crc32,
    'merkle_sha256': merkle_sha256
}
