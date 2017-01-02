
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
#include "flea/hash.h"

flea_err_t THR_flea_md5_compression_function( flea_hash_ctx_t* ctx__pt, const flea_u8_t* input);

void flea_md5_init( flea_hash_ctx_t* ctx__pt);

void flea_md5_encode_hash_state(const flea_hash_ctx_t* ctx__pt, flea_u8_t* output,  flea_al_u8_t output_len);
