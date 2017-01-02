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

#ifndef _flea_ec_key_gen__H_
#define _flea_ec_key_gen__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate an EC key pair.
 *
 * @param result_public pointer to the memory area where to store the resulting public key
 * @param result_public_len the caller must provide a pointer to a value representing
 * the available length in result_public, upon function return this value will
 * be updated with the length of the data written to result_public
 * @param result_private pointer to the memory area where to store the resulting private key
 * @param result_private_len the caller must provide a pointer to a value representing
 * the available length in result_private, upon function return this value will
 * be updated with the length of the data written to result_private
 * @param dp pointer to the domain parameters in flea's internal format
 *
 * @result flea error code
 */
flea_err_t THR_flea_generate_ecc_key(flea_u8_t* result_public, flea_al_u8_t* result_public_len, flea_u8_t* result_private, flea_al_u8_t* result_private_len, const flea_u8_t* dp);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
