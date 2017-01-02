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



#ifndef _flea_hash_int__H_
#define _flea_hash_int__H_

#include "flea/hash_fwd.h"
#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* internal function pointer types */
typedef flea_err_t (*THR_flea_hash_compression_f)(flea_hash_ctx_t* ctx, const flea_u8_t* input);
typedef void (*flea_hash_init_f)(flea_hash_ctx_t* ctx);
typedef void (*flea_hash_encode_hash_state_f)(const flea_hash_ctx_t* ctx, flea_u8_t* output, flea_al_u8_t output_len);

struct struct_flea_hash_config_entry_t;
typedef struct struct_flea_hash_config_entry_t flea_hash_config_entry_t;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
