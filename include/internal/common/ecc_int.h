
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


#ifndef _flea_ecc_int__H_
#define _flea_ecc_int__H_
#include "internal/common/default.h"

/**
 * According to Hasse's theorem, the base point order can be larger than p by
 * one bit
 */
#define FLEA_ECC_MAX_ORDER_BIT_SIZE (FLEA_ECC_MAX_MOD_BIT_SIZE + 1)

#define FLEA_ECC_MAX_MOD_BYTE_SIZE FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_MOD_BIT_SIZE)
#define FLEA_ECC_MAX_MOD_WORD_SIZE FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_MOD_BYTE_SIZE)

#define FLEA_ECC_MAX_ORDER_BYTE_SIZE FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(FLEA_ECC_MAX_ORDER_BIT_SIZE)
#define FLEA_ECC_MAX_ORDER_WORD_SIZE FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(FLEA_ECC_MAX_ORDER_BYTE_SIZE)

#endif /* h-guard */
