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


#include "flea/types.h"

// computes ~crc16
// initial remainder shall be zero for CCIT compatibility
flea_u16_t flea_crc16_ccit_compute (flea_u16_t crc_init__u16, const flea_u8_t* data__pcu8, flea_dtl_t data_len__dtl)
{
  flea_dtl_t i;

  for(i = 0; i < data_len__dtl; i++)
  {
    flea_al_s8_t j;
    flea_u8_t byte = data__pcu8[i];

    crc_init__u16 ^= (byte << 8);
    for(j = 0; j < 8; j++)
    {
      flea_u16_t mask__u16 = -(((crc_init__u16 ) & (1 << 15)) >> 15);
      crc_init__u16 = (crc_init__u16 << 1) ^ (0x1021 & mask__u16);
      byte <<= 1;
    }
  }
  return crc_init__u16;
}
