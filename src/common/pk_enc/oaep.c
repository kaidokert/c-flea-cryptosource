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
#include "internal/common/pk_enc/oaep.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/rng.h"
#include "flea/alloc.h"
#include "flea/algo_config.h"
#include "flea/error_handling.h"
#include "flea/hash.h"
#include <string.h>

flea_err_t THR_flea_pkcs1_mgf1 (flea_u8_t* output__pu8, flea_al_u16_t output_len__alu16, const flea_u8_t* seed__pc_u8, flea_al_u16_t seed_len__alu16, flea_hash_id_t hash_id__t)
{
  flea_al_u16_t nb_blocks;
  flea_al_u16_t i;

  flea_al_u16_t hash_len__alu16_t;

  FLEA_DECL_OBJ(ctx__t, flea_hash_ctx_t);
  FLEA_DECL_BUF(hash_out__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx__t, hash_id__t));
  hash_len__alu16_t = flea_hash_ctx_t__get_output_length(&ctx__t);
  FLEA_ALLOC_BUF(hash_out__bu8, hash_len__alu16_t);
  nb_blocks = (output_len__alu16 + hash_len__alu16_t - 1) / hash_len__alu16_t;
  for(i = 0; i < nb_blocks; i++)
  {
    flea_u8_t enc__a_u8[4];
    flea_al_u16_t this_iter_len__alu16;
    flea__encode_U32_BE(i, enc__a_u8);

    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, seed__pc_u8, seed_len__alu16));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, enc__a_u8, sizeof(enc__a_u8)));
    this_iter_len__alu16 = FLEA_MIN(output_len__alu16, hash_len__alu16_t);
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx__t, hash_out__bu8));
    flea__xor_bytes_in_place(output__pu8, hash_out__bu8, this_iter_len__alu16);
    flea_hash_ctx_t__reset(&ctx__t);
    output__pu8 += this_iter_len__alu16;
    output_len__alu16 -= this_iter_len__alu16;
  }

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx__t);
    FLEA_FREE_BUF_FINAL(hash_out__bu8);
    );
}
flea_err_t THR_flea_pk_api__encode_message__oaep (flea_u8_t* input_output__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t* output_len__palu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t)
{
  flea_al_u16_t k__alu16;
  flea_al_u16_t pad__alu16;
  flea_al_u16_t ps_offs__alu16;
  flea_al_u16_t ps_len__alu16;
  flea_al_u16_t db_len__alu16;
  flea_al_u16_t lhash_offs__alu16;
  flea_al_u8_t hash_output_len__alu8;
  flea_al_u16_t message_offs__alu16;

  FLEA_THR_BEG_FUNC();
  k__alu16 = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size__alu16);
  hash_output_len__alu8 = flea_hash__get_output_length_by_id(hash_id__t);
  // prevent overflow by limiting input_len__alu16
  if(input_len__alu16 > 16000 / 8)
  {
    FLEA_THROW("invalid input length to OAEP encoding", FLEA_ERR_INV_ARG);
  }
  if(*output_len__palu16 < k__alu16)
  {
    FLEA_THROW("output buffer too small in OAEP encoding", FLEA_ERR_BUFF_TOO_SMALL);
  }
  pad__alu16 = 2 * hash_output_len__alu8 + input_len__alu16 + 2;
  if(pad__alu16 > k__alu16)
  {
    FLEA_THROW("message too long in OAEP encoding", FLEA_ERR_INV_ARG);
  }
  // no underflows possible anymore
  ps_len__alu16 = k__alu16 - pad__alu16;
  message_offs__alu16 = k__alu16 - input_len__alu16;
  ps_offs__alu16 = message_offs__alu16 - ps_len__alu16 - 1;
  lhash_offs__alu16 = ps_offs__alu16 - hash_output_len__alu8;
  memmove(input_output__pu8 + message_offs__alu16, input_output__pu8, input_len__alu16);
  input_output__pu8[  message_offs__alu16 - 1] = 0x01;
  memset(input_output__pu8 + ps_offs__alu16, 0, ps_len__alu16);
  FLEA_CCALL(THR_flea_compute_hash(hash_id__t, input_output__pu8, 0, input_output__pu8 + lhash_offs__alu16, hash_output_len__alu8 ));
  db_len__alu16 = k__alu16 - hash_output_len__alu8 - 1;

  //gen seed in output buffer
  flea_rng__randomize(input_output__pu8 + 1, hash_output_len__alu8);

  FLEA_CCALL(THR_flea_pkcs1_mgf1(input_output__pu8 + lhash_offs__alu16, db_len__alu16, input_output__pu8 + 1, hash_output_len__alu8,  hash_id__t));
  FLEA_CCALL(THR_flea_pkcs1_mgf1(input_output__pu8 + 1, hash_output_len__alu8, input_output__pu8 + lhash_offs__alu16,  db_len__alu16, hash_id__t));
  input_output__pu8[0] = 0x00;

  *output_len__palu16 = k__alu16;
  FLEA_THR_FIN_SEC_empty();
}

// will destroy input content
flea_err_t THR_flea_pk_api__decode_message__oaep (flea_u8_t* result__pu8, flea_al_u16_t* result_len__palu16, flea_u8_t* input__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t)
{
  flea_al_u16_t db_len__alu16;
  flea_al_u16_t lhash_offs__alu16;
  flea_al_u8_t hash_output_len__alu8;
  flea_u8_t* message__pu8;
  flea_al_u16_t message_len__alu16;

  FLEA_DECL_BUF(lhash__bu8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);
  flea_al_u8_t error__alu8 = 0;
  FLEA_THR_BEG_FUNC();

  error__alu8 |= input__pu8[0];

  hash_output_len__alu8 = flea_hash__get_output_length_by_id(hash_id__t);

  lhash_offs__alu16 = hash_output_len__alu8 + 1;
  db_len__alu16 = input_len__alu16 - lhash_offs__alu16;
  FLEA_ALLOC_BUF(lhash__bu8, hash_output_len__alu8);
  FLEA_CCALL(THR_flea_compute_hash(hash_id__t, input__pu8, 0, lhash__bu8, hash_output_len__alu8 ));
  FLEA_CCALL(THR_flea_pkcs1_mgf1(&input__pu8[1], hash_output_len__alu8, input__pu8 + lhash_offs__alu16, db_len__alu16,  hash_id__t));
  FLEA_CCALL(THR_flea_pkcs1_mgf1(&input__pu8[lhash_offs__alu16], db_len__alu16, &input__pu8[1], hash_output_len__alu8, hash_id__t));
  // parse the unmasked db
  error__alu8 |= memcmp(&input__pu8[lhash_offs__alu16], lhash__bu8, hash_output_len__alu8);
  message_len__alu16 = input_len__alu16 - lhash_offs__alu16 - hash_output_len__alu8;
  message__pu8 = input__pu8 + lhash_offs__alu16 + hash_output_len__alu8;
  while((*message__pu8 == 0x00) && message_len__alu16)
  {
    message__pu8++;
    message_len__alu16--;
  }
  if(message_len__alu16 < 2)
  {
    error__alu8 |= 1;
  }
  else
  {
    if(*message__pu8 != 0x01)
    {
      error__alu8 |= 1;
    }
    else
    {
      message__pu8++;
      message_len__alu16--;
      if(*result_len__palu16 < message_len__alu16)
      {
        FLEA_THROW("oaep buffer for decoded message too small", FLEA_ERR_BUFF_TOO_SMALL);
      }
      if(!error__alu8)
      {
        memcpy(result__pu8, message__pu8, message_len__alu16);
      }
    }
  }
  if(error__alu8)
  {
    FLEA_THROW("OAEP decoding error", FLEA_ERR_INTEGRITY_FAILURE);
  }
  *result_len__palu16 = message_len__alu16;
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(lhash__bu8);
    );
}
