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


#ifndef _flea_block_cipher_int__H_
#define _flea_block_cipher_int__H_

#include "flea/error.h"
#include "flea/block_cipher_fwd.h"

#define FLEA_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE __FLEA_COMPUTED_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE

typedef void (*flea_cipher_block_processing_f)(const flea_ecb_mode_ctx_t* p_ctx, const flea_u8_t* input, flea_u8_t* output);

typedef flea_err_t (*THR_flea_block_cipher_key_sched_f)(flea_ecb_mode_ctx_t* ctx, const flea_u8_t* cipherKey);

struct struct_flea_block_cipher_config_entry_t;
typedef struct struct_flea_block_cipher_config_entry_t flea_block_cipher_config_entry_t;

typedef enum { des, aes } flea_block_cipher_raw_id_t;

struct struct_flea_block_cipher_config_entry_t
{
  flea_block_cipher_id_t ext_id__t;
  flea_block_cipher_raw_id_t raw_id__t;
  flea_u16_t key_bit_size;
  flea_u16_t expanded_key_u32_size__al_u16;

  flea_cipher_block_processing_f cipher_block_encr_function;
  flea_cipher_block_processing_f cipher_block_decr_function;

  THR_flea_block_cipher_key_sched_f THR_key_sched_encr_function;
  THR_flea_block_cipher_key_sched_f THR_key_sched_decr_function;

  flea_u8_t block_length__u8;

};


#endif /* h-guard */
