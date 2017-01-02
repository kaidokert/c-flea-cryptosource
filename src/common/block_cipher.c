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
#include "flea/block_cipher.h"
#include "flea/types.h"
#include "internal/common/block_cipher/aes.h"
#include "internal/common/block_cipher/des.h"
#include "internal/common/block_cipher/desx.h"
#include "internal/common/block_cipher/tdes.h"
#include "flea/util.h"
#include "flea/array_util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"
#include <string.h>
#include <stdlib.h>


const flea_block_cipher_config_entry_t block_cipher_config[] =
{
  {
    .ext_id__t = flea_aes128,
    .raw_id__t = aes,
    .key_bit_size = 128,
    .expanded_key_u32_size__al_u16 = 44,
    .cipher_block_encr_function = flea_aes_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_aes_setup_encr_key,
#ifdef FLEA_HAVE_AES_BLOCK_DECR
    .cipher_block_decr_function = flea_aes_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_aes_setup_decr_key,
#else
    .cipher_block_decr_function = NULL,
    .THR_key_sched_decr_function = NULL,
#endif
    .block_length__u8 = 16
  },
  {
    .ext_id__t = flea_aes192,
    .raw_id__t = aes,
    .key_bit_size = 192,
    .expanded_key_u32_size__al_u16 = 52,
    .cipher_block_encr_function = flea_aes_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_aes_setup_encr_key,
#ifdef FLEA_HAVE_AES_BLOCK_DECR
    .cipher_block_decr_function = flea_aes_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_aes_setup_decr_key,
#else
    .cipher_block_decr_function = NULL,
    .THR_key_sched_decr_function = NULL,
#endif
    .block_length__u8 = 16
  },
  {
    .ext_id__t = flea_aes256,
    .raw_id__t = aes,
    .key_bit_size = 256,
    .expanded_key_u32_size__al_u16 = 60,
    .cipher_block_encr_function = flea_aes_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_aes_setup_encr_key,
#ifdef FLEA_HAVE_AES_BLOCK_DECR
    .cipher_block_decr_function = flea_aes_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_aes_setup_decr_key,
#else
    .cipher_block_decr_function = NULL,
    .THR_key_sched_decr_function = NULL,
#endif
    .block_length__u8 = 16
  },
#ifdef FLEA_HAVE_DES
  {
    .ext_id__t = flea_des_single,
    .raw_id__t = des,
    .key_bit_size = 64, // 8 bits unused
    .expanded_key_u32_size__al_u16 = 32,
    .cipher_block_encr_function = flea_single_des_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_single_des_setup_key,
    .cipher_block_decr_function = flea_single_des_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_single_des_setup_key,
    .block_length__u8 = 8
  },
#ifdef FLEA_HAVE_TDES_2KEY
  {
    .ext_id__t = flea_tdes_2key,
    .raw_id__t = des,
    .key_bit_size = 128, // 16 bits unused
    .expanded_key_u32_size__al_u16 = 64,
    .cipher_block_encr_function = flea_triple_des_ede_2key_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_triple_des_ede_2key_setup_key,
    .cipher_block_decr_function = flea_triple_des_ede_2key_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_triple_des_ede_2key_setup_key,
    .block_length__u8 = 8
  },
#endif // #ifdef FLEA_HAVE_TDES_2KEY
#ifdef FLEA_HAVE_TDES_3KEY
  {
    .ext_id__t = flea_tdes_3key,
    .raw_id__t = des,
    .key_bit_size = 192, // 16 bits unused
    .expanded_key_u32_size__al_u16 = 96,
    .cipher_block_encr_function = flea_triple_des_ede_3key_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_triple_des_ede_3key_setup_key,
    .cipher_block_decr_function = flea_triple_des_ede_3key_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_triple_des_ede_3key_setup_key,
    .block_length__u8 = 8
  },
#endif // #ifdef FLEA_HAVE_TDES_3KEY
#ifdef FLEA_HAVE_DESX
  {
    .ext_id__t = flea_desx,
    .raw_id__t = des,
    .key_bit_size = 64 + 2 * 64, // 8 bits unused
    .expanded_key_u32_size__al_u16 = 32 + 4,
    .cipher_block_encr_function = flea_desx_encrypt_block,
    .THR_key_sched_encr_function = THR_flea_desx_setup_key,
    .cipher_block_decr_function = flea_desx_decrypt_block,
    .THR_key_sched_decr_function = THR_flea_desx_setup_key,
    .block_length__u8 = 8
  },
#endif  // #ifdef FLEA_HAVE_DESX
#endif  // #ifdef FLEA_HAVE_DES

};

static const flea_block_cipher_config_entry_t* flea_find_block_cipher_config (flea_block_cipher_id_t id)
{
  flea_al_u16_t i;

  for( i = 0; i < FLEA_NB_ARRAY_ENTRIES(block_cipher_config); i++)
  {
    if(block_cipher_config[i].ext_id__t == id)
    {
      return &block_cipher_config[i];
    }
  }
  return NULL;
}

flea_al_u8_t flea_block_cipher__get_key_size (flea_block_cipher_id_t id)
{
  return flea_find_block_cipher_config(id)->key_bit_size / 8;
}
flea_al_u8_t flea_block_cipher__get_block_size (flea_block_cipher_id_t id)
{
  return flea_find_block_cipher_config(id)->block_length__u8;
}


void flea_ecb_mode_ctx_t__dtor (flea_ecb_mode_ctx_t* ctx__pt)
{
  if(ctx__pt->config__pt == NULL)
  {
    return;
  }
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->expanded_key__bu8, ctx__pt->config__pt->expanded_key_u32_size__al_u16);
}

flea_err_t THR_flea_ecb_mode_ctx_t__ctor (flea_ecb_mode_ctx_t* p_ctx, flea_block_cipher_id_t ext_id__t, const flea_u8_t* key, flea_al_u16_t key_byte_length, flea_cipher_dir_t dir)
{
  FLEA_THR_BEG_FUNC();

  const flea_block_cipher_config_entry_t* config__p_t = flea_find_block_cipher_config(ext_id__t);
  if(config__p_t == NULL)
  {
    FLEA_THROW("invalid block cipher id", FLEA_ERR_INV_ALGORITHM);
  }
  p_ctx->config__pt = config__p_t;
  p_ctx->block_length__u8 = config__p_t->block_length__u8;
  p_ctx->dir__t = dir;
  if(key_byte_length * 8 != config__p_t->key_bit_size)
  {
    FLEA_THROW("invalid key length provided", FLEA_ERR_INV_ARG);
  }
  p_ctx->key_byte_size__u8 = key_byte_length;
  if(dir == flea_encrypt)
  {
    p_ctx->block_crypt_f = config__p_t->cipher_block_encr_function;
  }
  else
  {
    p_ctx->block_crypt_f = config__p_t->cipher_block_decr_function;
  }
  if(p_ctx->block_crypt_f == NULL || p_ctx->block_crypt_f == NULL)
  {
    FLEA_THROW("trying to create cipher-ctx for unsupported direction", FLEA_ERR_INV_ALGORITHM);
  }
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(p_ctx->expanded_key__bu8, config__p_t->expanded_key_u32_size__al_u16);
#endif
  if(dir == flea_encrypt)
  {
    FLEA_CCALL(config__p_t->THR_key_sched_encr_function(p_ctx, key));
  }
  else
  {
    // assumed to be not NULL if the decryption function is not NULL
    FLEA_CCALL(config__p_t->THR_key_sched_decr_function(p_ctx, key));
  }
  FLEA_THR_FIN_SEC_empty();

}
flea_err_t THR_flea_ecb_mode_crypt_data (flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8, flea_dtl_t data_len__al_u16)
{
  flea_al_u8_t block_length__al_u8 = ctx__p_t->block_length__u8;

  FLEA_THR_BEG_FUNC();
  if(data_len__al_u16 % block_length__al_u8)
  {
    FLEA_THROW("data provided for ECB en-/decryption is not a multiple of the block size", FLEA_ERR_INV_ARG);
  }
  while(data_len__al_u16)
  {
    ctx__p_t->block_crypt_f(ctx__p_t, input__pc_u8, output__p_u8);
    data_len__al_u16 -= block_length__al_u8;
    input__pc_u8 += block_length__al_u8;
    output__p_u8 += block_length__al_u8;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ctr_mode_ctx_t__ctor (flea_ctr_mode_ctx_t* p_ctx, flea_block_cipher_id_t ext_id__t, const flea_u8_t* key_pu8, flea_al_u8_t key_length_al_u8, const flea_u8_t* nonce_pu8, flea_al_u8_t nonce_length_al_u8 )
{
  flea_al_u8_t block_length_al_u8;

  FLEA_THR_BEG_FUNC();
  flea_ecb_mode_ctx_t__INIT(&p_ctx->cipher_ctx__t);

  const flea_block_cipher_config_entry_t* config__pt = flea_find_block_cipher_config(ext_id__t);
  if(config__pt == NULL)
  {
    FLEA_THROW("invalid block cipher id", FLEA_ERR_INV_ARG);
  }
  block_length_al_u8 = config__pt->block_length__u8;
  if(nonce_length_al_u8 > block_length_al_u8)
  {
    FLEA_THROW("nonce length greater than block length", FLEA_ERR_INV_ARG);
  }
  FLEA_CCALL(THR_flea_ecb_mode_ctx_t__ctor(&p_ctx->cipher_ctx__t, ext_id__t, key_pu8, key_length_al_u8, flea_encrypt));
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM(p_ctx->ctr_block__bu8, block_length_al_u8);
  FLEA_ALLOC_MEM(p_ctx->pending_mask__bu8, block_length_al_u8);
#endif
  memset(p_ctx->ctr_block__bu8, 0, block_length_al_u8);
  memcpy(p_ctx->ctr_block__bu8, nonce_pu8, nonce_length_al_u8);

  p_ctx->pending_offset__alu8 = block_length_al_u8; // no byte pending

  p_ctx->config__pt = config__pt;
  FLEA_THR_FIN_SEC_empty();
}

void flea_ctr_mode_ctx_t__dtor (flea_ctr_mode_ctx_t* p_ctx)
{
  if(p_ctx->cipher_ctx__t.config__pt == NULL)
  {
    return;
  }
  flea_al_u8_t block_len__alu8 = p_ctx->config__pt->block_length__u8;
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(p_ctx->ctr_block__bu8, block_len__alu8);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(p_ctx->pending_mask__bu8, block_len__alu8);

  flea_ecb_mode_ctx_t__dtor(&p_ctx->cipher_ctx__t);
}

void flea_ctr_mode_ctx_t__crypt (flea_ctr_mode_ctx_t* p_ctx, const flea_u8_t* input_pu8, flea_u8_t* output_pu8, flea_dtl_t input_output_length_al_u16)
{
  flea_al_u16_t nb_blocks_al_u16;
  flea_al_u8_t block_length_al_u8;
  flea_al_u8_t tail_al_u8, head_al_u8, pending_offset__alu8, i;
  flea_u8_t* pending_mask__bu8;
  flea_cipher_block_processing_f block_function;

  block_function = p_ctx->config__pt->cipher_block_encr_function;
  block_length_al_u8 = p_ctx->config__pt->block_length__u8;

  // use up pending mask bytes first
  head_al_u8 = block_length_al_u8 - p_ctx->pending_offset__alu8;
  if(head_al_u8 > input_output_length_al_u16)
  {
    head_al_u8 = input_output_length_al_u16;
  }
  pending_offset__alu8 = p_ctx->pending_offset__alu8;
  pending_mask__bu8 = p_ctx->pending_mask__bu8;
  flea__xor_bytes(output_pu8, input_pu8, pending_mask__bu8 + pending_offset__alu8, head_al_u8);
  input_output_length_al_u16 -= head_al_u8;
  input_pu8 += head_al_u8;
  output_pu8 += head_al_u8;
  p_ctx->pending_offset__alu8 += head_al_u8;

  // number of full blocks:
  nb_blocks_al_u16 = (input_output_length_al_u16) / block_length_al_u8;
  // process full blocks
  for(i = 0; i < nb_blocks_al_u16; i++)
  {
    block_function(&p_ctx->cipher_ctx__t, p_ctx->ctr_block__bu8, pending_mask__bu8);
    flea__xor_bytes(output_pu8, input_pu8, pending_mask__bu8, block_length_al_u8);
    flea__increment_encoded_BE_int(p_ctx->ctr_block__bu8, block_length_al_u8);
    output_pu8 += block_length_al_u8;
    input_pu8 += block_length_al_u8;
  }
  tail_al_u8 = input_output_length_al_u16 % block_length_al_u8;
  if(tail_al_u8)
  {
    block_function(&p_ctx->cipher_ctx__t, p_ctx->ctr_block__bu8, pending_mask__bu8);
    flea__xor_bytes(output_pu8, input_pu8, pending_mask__bu8, tail_al_u8);
    p_ctx->pending_offset__alu8 = tail_al_u8;
    flea__increment_encoded_BE_int(p_ctx->ctr_block__bu8, block_length_al_u8);
  }


}


flea_err_t THR_flea_ctr_mode_crypt_data (flea_block_cipher_id_t ext_id__t, const flea_u8_t* key_pu8, flea_al_u16_t key_length_al_u16, const flea_u8_t* nonce__pcu8, flea_al_u8_t nonce_len__alu8, const flea_u8_t* input_pu8, flea_u8_t* output_pu8, flea_dtl_t input_output_length_al_u16)
{
  FLEA_DECL_OBJ(ctx, flea_ctr_mode_ctx_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, ext_id__t, key_pu8, key_length_al_u16, nonce__pcu8, nonce_len__alu8 ));
  flea_ctr_mode_ctx_t__crypt(&ctx, input_pu8, output_pu8, input_output_length_al_u16);
  FLEA_THR_FIN_SEC(
    flea_ctr_mode_ctx_t__dtor(&ctx);
    );
}

flea_err_t THR_flea_ctr_mode_crypt_data_short_nonce (flea_block_cipher_id_t ext_id__t, const flea_u8_t* key_pu8, flea_al_u16_t key_length_al_u16, flea_u32_t nonce_u32, const flea_u8_t* input_pu8, flea_u8_t* output_pu8, flea_dtl_t input_output_length_al_u16)
{

  flea_u8_t enc_nonce[4];

  FLEA_THR_BEG_FUNC();
  flea__encode_U32_BE(nonce_u32, enc_nonce);
  FLEA_CCALL(THR_flea_ctr_mode_crypt_data(ext_id__t, key_pu8, key_length_al_u16, enc_nonce, sizeof(enc_nonce), input_pu8, output_pu8, input_output_length_al_u16));
  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_cbc_mode_ctx_t__ctor (flea_cbc_mode_ctx_t* ctx__pt, flea_block_cipher_id_t id__t, const flea_u8_t* key__pcu8, flea_al_u8_t key_len__alu8, const flea_u8_t* iv__pcu8, flea_al_u8_t iv_len__alu8, flea_cipher_dir_t dir__t )
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ecb_mode_ctx_t__ctor(&ctx__pt->cipher_ctx__t, id__t, key__pcu8, key_len__alu8, dir__t));
  if(iv_len__alu8 != ctx__pt->cipher_ctx__t.block_length__u8)
  {
    FLEA_THROW("invalid IV length in CBC mode", FLEA_ERR_INV_ARG);
  }
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ctx__pt->iv__bu8, ctx__pt->cipher_ctx__t.block_length__u8);
#endif
  memcpy(ctx__pt->iv__bu8, iv__pcu8, iv_len__alu8);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_cbc_mode_ctx_t__crypt (flea_cbc_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8, flea_dtl_t input_output_len__dtl)
{
  flea_dtl_t nb_blocks__dtl, i;

  FLEA_THR_BEG_FUNC();
  FLEA_DECL_BUF(decr_block__bu8, flea_u8_t, FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH);
  flea_al_u8_t block_len__alu8 = ctx__pt->cipher_ctx__t.block_length__u8;
  if(input_output_len__dtl % block_len__alu8)
  {
    FLEA_THROW("input/output data length is not a multiple of the block size in CBC", FLEA_ERR_INV_ARG);
  }
  nb_blocks__dtl = input_output_len__dtl / block_len__alu8;
  if(nb_blocks__dtl == 0)
  {
    FLEA_THR_RETURN();
  }
  if(ctx__pt->cipher_ctx__t.dir__t == flea_encrypt)
  {
    flea_u8_t* iv__pu8 = ctx__pt->iv__bu8;
    for(i = 0; i < nb_blocks__dtl; i++)
    {
      flea__xor_bytes(output__pu8, iv__pu8, input__pcu8, block_len__alu8 );
      ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, output__pu8, output__pu8);
      iv__pu8 = output__pu8;
      input__pcu8 += block_len__alu8;
      output__pu8 += block_len__alu8;
    }
    memcpy(ctx__pt->iv__bu8, output__pu8 - block_len__alu8, block_len__alu8);
  }
  else // decrypt
  {
    FLEA_ALLOC_BUF(decr_block__bu8, block_len__alu8);
    const flea_u8_t* iv__pu8 = ctx__pt->iv__bu8;
    input__pcu8 += input_output_len__dtl - block_len__alu8;
    output__pu8 += input_output_len__dtl - block_len__alu8;
    // save the new IV
    memcpy(decr_block__bu8, input__pcu8, block_len__alu8);
    // ^ both now point to the last block
    for(i = nb_blocks__dtl - 1; i >= 1; i--)
    {
      ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, input__pcu8, output__pu8);
      flea__xor_bytes_in_place(output__pu8, input__pcu8 - block_len__alu8, block_len__alu8 );
      input__pcu8 -= block_len__alu8;
      output__pu8 -= block_len__alu8;
    }
    //handle final block
    ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, input__pcu8, output__pu8);
    flea__xor_bytes_in_place(output__pu8, iv__pu8, block_len__alu8 );

    memcpy(ctx__pt->iv__bu8, decr_block__bu8, block_len__alu8);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(decr_block__bu8);
    );
}

flea_err_t THR_flea_cbc_mode__crypt_data (flea_block_cipher_id_t id__t, const flea_u8_t* key__pcu8, flea_al_u8_t key_len__alu8, const flea_u8_t* iv__pcu8, flea_al_u8_t iv_len__alu8, flea_cipher_dir_t dir__t, flea_u8_t* output__pu8, const flea_u8_t* input__pcu8, flea_dtl_t input_output_len__dtl)
{
  FLEA_DECL_OBJ(ctx__t, flea_cbc_mode_ctx_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__alu8, iv__pcu8, iv_len__alu8, dir__t));
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&ctx__t, input__pcu8, output__pu8, input_output_len__dtl));
  FLEA_THR_FIN_SEC(
    flea_cbc_mode_ctx_t__dtor(&ctx__t);
    );
}

flea_err_t THR_flea_cbc_mode__encrypt_data (flea_block_cipher_id_t id__t, const flea_u8_t* key__pcu8, flea_al_u8_t key_len__alu8, const flea_u8_t* iv__pcu8, flea_al_u8_t iv_len__alu8, flea_u8_t* output__pu8, const flea_u8_t* input__pcu8, flea_dtl_t input_output_len__dtl)
{
  return THR_flea_cbc_mode__crypt_data(id__t, key__pcu8, key_len__alu8, iv__pcu8, iv_len__alu8, flea_encrypt, output__pu8, input__pcu8, input_output_len__dtl);
}

flea_err_t THR_flea_cbc_mode__decrypt_data (flea_block_cipher_id_t id__t, const flea_u8_t* key__pcu8, flea_al_u8_t key_len__alu8, const flea_u8_t* iv__pcu8, flea_al_u8_t iv_len__alu8, flea_u8_t* output__pu8, const flea_u8_t* input__pcu8, flea_dtl_t input_output_len__dtl)
{
  return THR_flea_cbc_mode__crypt_data(id__t, key__pcu8, key_len__alu8, iv__pcu8, iv_len__alu8, flea_decrypt, output__pu8, input__pcu8, input_output_len__dtl);
}

void flea_cbc_mode_ctx_t__dtor (flea_cbc_mode_ctx_t* ctx__pt)
{
  flea_ecb_mode_ctx_t__dtor(&ctx__pt->cipher_ctx__t);
  // IV is not considered a secret
#ifdef FLEA_USE_HEAP_BUF
  FLEA_FREE_MEM_CHK_SET_NULL(ctx__pt->iv__bu8);
#endif
}

