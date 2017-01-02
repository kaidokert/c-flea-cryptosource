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


#ifndef __flea_error_H_
#define __flea_error_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef enum
{
  FLEA_ERR_FINE    =    0,
  FLEA_ERR_INT_ERR  =   0x0001,
  FLEA_ERR_INV_STATE =   0x0002,
  FLEA_ERR_FAILED_TEST =  0x0003,
  FLEA_ERR_INTEGRITY_FAILURE  = 0x0004,
  FLEA_ERR_INV_SIGNATURE  = 0x0005,
  FLEA_ERR_INV_ARG                 = 0x0006,
  FLEA_ERR_INV_ALGORITHM        = 0x0008,
  FLEA_ERR_INV_MAC             = 0x0009,
  FLEA_ERR_POINT_NOT_ON_CURVE  = 0x000A,
  FLEA_ERR_INV_ECC_DP          = 0x000B,
  FLEA_ERR_INV_KEY_SIZE        = 0x000C,
  FLEA_ERR_ZERO_POINT_AFF_TRF    = 0x0020,
  FLEA_ERR_BUFF_TOO_SMALL           = 0x00A0,
  FLEA_ERR_DECODING_FAILURE     = 0x00A1,
  FLEA_ERR_PRNG_NVM_WRITE_ERROR = 0x00B1,
  FLEA_ERR_RNG_NOT_SEEDED       = 0x00B2,
  FLEA_ERR_OUT_OF_MEM               = 0x00FF

} flea_err_t;

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
