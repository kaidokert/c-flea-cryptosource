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


#include "internal/common/build_config.h"
#include "flea/block_cipher.h"
#include "flea/ctr_mode_prng.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/util.h"
#include "flea/bin_utils.h"
#include "flea/alloc.h"
#include "flea/block_cipher.h"
#include "flea/error_handling.h"




static void flea_ctr_mode_prng_t__reset (flea_ctr_mode_prng_t* ctx__pt)
{
  ctx__pt->pending_seed_len__u8 = 0;
  ctx__pt->pending_output_len__u8 = 0;
  ctx__pt->round_key_index__u8 = 0;
  memset(ctx__pt->count_block__bu8, 0, FLEA_AES_BLOCK_LENGTH);
  ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, ctx__pt->count_block__bu8, ctx__pt->count_block__bu8);


  flea_ctr_mode_prng_t__randomize_no_flush(ctx__pt, ctx__pt->reseed_buf__bu8, FLEA_AES_BLOCK_LENGTH);
}

flea_err_t THR_flea_ctr_mode_prng_t__ctor (flea_ctr_mode_prng_t* ctx__pt, const flea_u8_t* state__pcu8, flea_al_u8_t state_len__alu8)
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  FLEA_ALLOC_MEM_ARR(ctx__pt->pending_output__bu8, FLEA_AES_BLOCK_LENGTH);
  FLEA_ALLOC_MEM_ARR(ctx__pt->count_block__bu8, FLEA_AES_BLOCK_LENGTH);
  FLEA_ALLOC_MEM_ARR(ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_ALLOC_MEM_ARR(ctx__pt->reseed_buf__bu8, FLEA_AES_BLOCK_LENGTH);
#endif
  FLEA_CCALL(THR_flea_compute_hash(flea_sha256, state__pcu8, state_len__alu8, ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  FLEA_CCALL(THR_flea_ecb_mode_ctx_t__ctor(&ctx__pt->cipher_ctx__t, flea_aes256, ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH, flea_encrypt));
  flea_ctr_mode_prng_t__reset(ctx__pt);
  FLEA_THR_FIN_SEC_empty();
}

void flea_ctr_mode_prng_t__dtor (flea_ctr_mode_prng_t* ctx__pt)
{
  if(ctx__pt->cipher_ctx__t.expanded_key__bu8 == NULL)
  {
    return;
  }
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->pending_output__bu8, FLEA_AES_BLOCK_LENGTH);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->count_block__bu8, FLEA_AES_BLOCK_LENGTH);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(ctx__pt->reseed_buf__bu8, FLEA_AES_BLOCK_LENGTH);
  flea_ecb_mode_ctx_t__dtor(&ctx__pt->cipher_ctx__t);
}

void flea_ctr_mode_prng_t__randomize (flea_ctr_mode_prng_t* ctx__pt, flea_u8_t* mem__pu8, flea_dtl_t mem_len__dtl)
{
  flea_ctr_mode_prng_t__randomize_no_flush(ctx__pt, mem__pu8, mem_len__dtl);
  flea_ctr_mode_prng_t__flush(ctx__pt);
}

void flea_ctr_mode_prng_t__randomize_no_flush (flea_ctr_mode_prng_t* ctx__pt, flea_u8_t* mem__pu8, flea_dtl_t mem_len__dtl)
{
  flea_dtl_t nb_blocks__dtl, i;
  flea_u8_t* pending_ptr__pu8;

  flea_al_u8_t to_copy__alu8 = FLEA_MIN(mem_len__dtl, ctx__pt->pending_output_len__u8);

  pending_ptr__pu8 = ctx__pt->pending_output__bu8 + FLEA_AES_BLOCK_LENGTH - ctx__pt->pending_output_len__u8;
  memcpy(mem__pu8, pending_ptr__pu8, to_copy__alu8);

  ctx__pt->pending_output_len__u8 -= to_copy__alu8;
  mem_len__dtl -= to_copy__alu8;

  if(mem_len__dtl == 0)
  {
    return;
  }
  mem__pu8 += to_copy__alu8;


  nb_blocks__dtl = mem_len__dtl / FLEA_AES_BLOCK_LENGTH;
  for( i = 0; i < nb_blocks__dtl; i++)
  {
    flea__increment_encoded_BE_int(ctx__pt->count_block__bu8, FLEA_AES_BLOCK_LENGTH);
    ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, ctx__pt->count_block__bu8, mem__pu8 );
    mem__pu8 += FLEA_AES_BLOCK_LENGTH;
  }
  mem_len__dtl %= FLEA_AES_BLOCK_LENGTH;
  if(mem_len__dtl != 0)
  {
    flea__increment_encoded_BE_int(ctx__pt->count_block__bu8, FLEA_AES_BLOCK_LENGTH);
    ctx__pt->cipher_ctx__t.block_crypt_f(&ctx__pt->cipher_ctx__t, ctx__pt->count_block__bu8, ctx__pt->pending_output__bu8);
    memcpy(mem__pu8, ctx__pt->pending_output__bu8, mem_len__dtl);
    ctx__pt->pending_output_len__u8 = FLEA_AES_BLOCK_LENGTH - mem_len__dtl;
  }
}


flea_err_t THR_flea_ctr_mode_prng_t__reseed (flea_ctr_mode_prng_t* ctx__pt, const flea_u8_t* seed__pcu8, flea_dtl_t seed_len__dtl)
{
  FLEA_DECL_OBJ(hash_ctx__t, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&hash_ctx__t, flea_sha256));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx__t, ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&hash_ctx__t, seed__pcu8, seed_len__dtl ));
  FLEA_CCALL(THR_flea_hash_ctx_t__final_with_length_limit(&hash_ctx__t, ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  flea_aes_setup_encr_key(&ctx__pt->cipher_ctx__t, ctx__pt->key__bu8);
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&hash_ctx__t);
    );
}



void flea_ctr_mode_prng_t__flush (flea_ctr_mode_prng_t* ctx__pt)
{
  flea_ctr_mode_prng_t__randomize_no_flush(ctx__pt, ctx__pt->key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  flea_aes_setup_encr_key(&ctx__pt->cipher_ctx__t, ctx__pt->key__bu8);
  flea_ctr_mode_prng_t__reset(ctx__pt);
}


