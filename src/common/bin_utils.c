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


#include "internal/common/default.h"
#include "flea/bin_utils.h"
#include "flea/types.h"

void flea__xor_bytes_in_place (flea_u8_t* in_out, const flea_u8_t* in2, flea_dtl_t len)
{
  flea_dtl_t i;

  for(i = 0; i < len; i++)
  {
    in_out[i] ^= in2[i];
  }
}

void flea__xor_bytes (flea_u8_t* out, const flea_u8_t* in1, const flea_u8_t* in2, flea_dtl_t len__dtl)
{
  flea_dtl_t i;

  for(i = 0; i < len__dtl; i++)
  {
    out[i] = in1[i] ^ in2[i];
  }
}

void flea__encode_U32_LE (flea_u32_t to_enc, flea_u8_t res[4])
{
  res[3] = to_enc >> 24;
  res[2] = to_enc >> 16;
  res[1] = to_enc >> 8;
  res[0] = to_enc & 0xFF;
}

void flea__encode_U32_BE (flea_u32_t to_enc, flea_u8_t res[4])
{
  res[0] = to_enc >> 24;
  res[1] = to_enc >> 16;
  res[2] = to_enc >> 8;
  res[3] = to_enc & 0xFF;
}

flea_u32_t flea__decode_U32_BE (const flea_u8_t enc[4])
{
  return ((flea_u32_t)enc[0] << 24) |
         ((flea_u32_t)enc[1] << 16) |
         ((flea_u32_t)enc[2] << 8 ) |
         ((flea_u32_t)(enc[3] & 0xFF));

}

void flea__increment_encoded_BE_int (flea_u8_t* ctr_block_pu8, flea_al_u8_t ctr_block_length_al_u8)
{
  flea_al_s8_t i;

  for(i = ctr_block_length_al_u8 - 1; i >= 0; i--)
  {
    flea_u8_t old_u8 = ctr_block_pu8[i];
    ctr_block_pu8[i] += 1;
    if(ctr_block_pu8[i] > old_u8)
    {
      // no overflow
      break;
    }
  }
}

flea_al_u8_t flea__nlz_uword (flea_uword_t x)
{
  flea_al_u8_t n = sizeof(flea_uword_t) * 8;  // i.e. 32 for 32-bit
  flea_al_u8_t c = sizeof(flea_uword_t) * 4;  // i.e. 16 for 32-bit

  do
  {
    flea_uword_t y;
    y = x >> c;
    if( y != 0)
    {
      n = n - c;
      x = y;
    }
    c = c >> 1;
  }
  while(c != 0);
  return n - x;
}

flea_mpi_ulen_t flea__get_BE_int_bit_len (const flea_u8_t* enc__pcu8, flea_mpi_ulen_t int_len__mpl)
{
  flea_mpi_ulen_t i;

  for(i = 0; i < int_len__mpl; i++)
  {
    if(enc__pcu8[i])
    {
      flea_al_s8_t j;
      for(j = 7; j >= 0; j--)
      {
        if(enc__pcu8[i] & (1 << j))
        {
          return j + 1 + (int_len__mpl - 1 - i) * 8;
        }
      }
    }
  }
  return 0;
}
