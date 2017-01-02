/*
__________________
***** cryptosource
******************
  Cryptography. Security.

    flea cryptographic library for embedded systems
    Copyright (C) 2015 cryptosource GmbH

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _flea_crc__H_
#define _flea_crc__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Compute the CRC16 (CCIT) checksum of the given data.
 *
 * @param crc_init CRC start value
 * @param data pointer to the data to compute the checksum of
 * @param data_len length of data
 */
flea_u16_t flea_crc16_ccit_compute(flea_u16_t crc_init, const flea_u8_t* data, flea_dtl_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
