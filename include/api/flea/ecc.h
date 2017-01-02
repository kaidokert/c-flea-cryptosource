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


#ifndef _flea_ecc__H_
#define _flea_ecc__H_
#include "internal/common/default.h"
#include "internal/common/ecc_int.h"

/**
 * The maximal size of an uncompressed or hybrid encoded EC point.
 */
#define FLEA_ECC_MAX_UNCOMPR_POINT_SIZE (2 * (FLEA_ECC_MAX_MOD_BYTE_SIZE)+1)

/**
 * The maximal byte size of an EC private key.
 */
#define FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE FLEA_ECC_MAX_ORDER_BYTE_SIZE

#endif /* h-guard */
