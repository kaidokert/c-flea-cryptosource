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


#ifndef _flea_sha256_H_
#define _flea_sha256_H_

#include "flea/types.h"
#include "flea/hash.h"

void flea_sha256_encode_hash_state(const flea_hash_ctx_t* ctx__t, flea_u8_t* output,  flea_al_u8_t output_len);

void flea_sha256_init( flea_hash_ctx_t* ctx__t);

void flea_sha224_init( flea_hash_ctx_t* ctx__t);

flea_err_t THR_flea_sha256_compression_function( flea_hash_ctx_t* ctx__t, const flea_u8_t* input);

#endif /* h-guard */
