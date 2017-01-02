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


#ifndef _flea_mac_int__H_
#define _flea_mac_int__H_

#include "internal/common/default.h"
#include "flea/mac_fwd.h"

typedef enum { flea_cmac, flea_hmac } flea_mac_mode_id_t;

typedef struct
{
  flea_hash_ctx_t hash_ctx__t;
  flea_u8_t hash_output_len__u8;
  flea_u8_t key_byte_len__u8;
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* key__bu8;
#else
  flea_u8_t key__bu8[__FLEA_COMPUTED_MAC_MAX_KEY_LEN];
#endif

} flea_mac_ctx_hmac_specific_t;

typedef struct
{
  flea_u8_t pending__u8;
  flea_ecb_mode_ctx_t cipher_ctx__t;

#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* prev_ct__bu8;
#else
  flea_u8_t prev_ct__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif

} flea_mac_ctx_cmac_specific_t;


struct mac_config_entry_struct;
typedef struct mac_config_entry_struct mac_config_entry_t;

void flea_mac_ctx_t__dtor_cipher_ctx_ref(flea_mac_ctx_t* ctx__pt);

void flea_mac_ctx_t__reset_cmac(flea_mac_ctx_t* ctx__pt);

flea_err_t THR_flea_mac_ctx_t__ctor_cmac(flea_mac_ctx_t* ctx, const mac_config_entry_t* config_entry, const flea_u8_t* key, flea_al_u16_t key_len, flea_ecb_mode_ctx_t* ciph_ctx_ref);

#endif /* h-guard */
