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
#include "flea/ae.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include "internal/common/mac_int2.h"


#ifdef FLEA_HAVE_AE
typedef enum { eax } flea_ae_mode_t;

struct flea_ae_config_entry_struct
{
  flea_ae_id_t ae_id__t;
  flea_ae_mode_t ae_mode__t;
  flea_block_cipher_id_t cipher_id__t;
  flea_mac_id_t mac_id__t;
};

const flea_ae_config_entry_t ae_config__at[] =
{
#ifdef FLEA_HAVE_CMAC
  {
    .ae_id__t = flea_eax_aes128,
    .ae_mode__t = eax,
    .cipher_id__t = flea_aes128,
    .mac_id__t = flea_cmac_aes128
  },
#endif
};
const flea_ae_config_entry_t* flea_find_ae_config (flea_ae_id_t id__t)
{
  flea_al_u16_t i;

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ae_config__at); i++)
  {
    if(id__t == ae_config__at[i].ae_id__t)
    {
      return &ae_config__at[i];
    }
  }
  return NULL;
}

/**
 * Helper function for the setting up of the EAX OMAC values.
 * result must have the output length of the MAC allocated, which must be equal
 * to the cipher's block length.
 * resets the mac_ctx__t after the computation
 */
static flea_err_t THR_flea_ae__compute_omac_indexed (flea_mac_ctx_t* mac_ctx__t, flea_u8_t index__u8, flea_al_u8_t block_len__alu8, const flea_u8_t* data__pcu8, flea_dtl_t data_len__dtl, flea_u8_t* result__pu8)
{
  flea_al_u8_t i;

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < block_len__alu8 - 1; i++)
  {
    flea_u8_t zero = 0;
    FLEA_CCALL(THR_flea_mac_ctx_t__update(mac_ctx__t, &zero, 1));
  }
  FLEA_CCALL(THR_flea_mac_ctx_t__update(mac_ctx__t, &index__u8, 1));
  if(index__u8 != 2)
  {
    flea_al_u8_t cp_block_len__alu8 = block_len__alu8;
    FLEA_CCALL(THR_flea_mac_ctx_t__update(mac_ctx__t, data__pcu8, data_len__dtl));
    FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(mac_ctx__t, result__pu8, &cp_block_len__alu8));
    flea_mac_ctx_t__reset_cmac(mac_ctx__t);
  }
  FLEA_THR_FIN_SEC_empty();
}
/**
 *
 * supports nonce lengths of up to the cipher's block length
 */
flea_err_t THR_flea_ae_ctx_t__ctor (flea_ae_ctx_t* ctx__pt, flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_al_u16_t key_len__alu16, const flea_u8_t* nonce__pcu8, flea_al_u8_t nonce_len__alu8, const flea_u8_t* header__pcu8, flea_dtl_t header_len__dtl, flea_al_u8_t tag_length__alu8)
{
  FLEA_THR_BEG_FUNC();

  const flea_ae_config_entry_t* config__pt = flea_find_ae_config(id__t);

  if(config__pt == NULL)
  {
    FLEA_THROW("AE config not found", FLEA_ERR_INV_ALGORITHM);
  }
  if(config__pt->ae_mode__t == eax)
  {
    flea_ctr_mode_ctx_t__INIT(&ctx__pt->mode_specific__u.eax.ctr_ctx__t);
    flea_mac_ctx_t__INIT(&ctx__pt->mode_specific__u.eax.cmac_ctx__t);
    ctx__pt->mode_specific__u.eax.pending__u8 = 0;
#ifdef FLEA_USE_HEAP_BUF
    ctx__pt->mode_specific__u.eax.nonce__bu8 = NULL;
    ctx__pt->mode_specific__u.eax.header_omac__bu8 = NULL;
    ctx__pt->mode_specific__u.eax.buffer__bu8 = NULL;
#endif
  }
  ctx__pt->config__pt = config__pt;
  ctx__pt->tag_len__u8 = tag_length__alu8; // indicates to the dtor that members are initialized
  if(config__pt->ae_mode__t == eax)
  {
    const mac_config_entry_t* mac_config__pct = flea_mac__find_mac_config(config__pt->mac_id__t);
    flea_al_u8_t block_len__alu8;
    if(mac_config__pct == NULL)
    {
      FLEA_THROW("AE: MAC config not found", FLEA_ERR_INV_ALGORITHM);
    }
    FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx__pt->mode_specific__u.eax.ctr_ctx__t, config__pt->cipher_id__t, key__pcu8, key_len__alu16, nonce__pcu8, nonce_len__alu8));
    FLEA_CCALL(THR_flea_mac_ctx_t__ctor_cmac(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, mac_config__pct, key__pcu8, key_len__alu16, &ctx__pt->mode_specific__u.eax.ctr_ctx__t.cipher_ctx__t));
    if(tag_length__alu8 > ctx__pt->mode_specific__u.eax.cmac_ctx__t.output_len__u8)
    {
      FLEA_THROW("specified tag length exceeds CMAC's output length", FLEA_ERR_INV_ARG);
    }
    block_len__alu8 = ctx__pt->mode_specific__u.eax.ctr_ctx__t.cipher_ctx__t.block_length__u8;
#ifdef FLEA_USE_HEAP_BUF
    FLEA_ALLOC_MEM_ARR(ctx__pt->mode_specific__u.eax.nonce__bu8, block_len__alu8 );
    FLEA_ALLOC_MEM_ARR(ctx__pt->mode_specific__u.eax.header_omac__bu8, block_len__alu8 );
    FLEA_ALLOC_MEM_ARR(ctx__pt->mode_specific__u.eax.buffer__bu8, tag_length__alu8);
#endif
    // use the cmac ctx for the computation of the stored nonce
    FLEA_CCALL(THR_flea_ae__compute_omac_indexed(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, 0, block_len__alu8, nonce__pcu8, nonce_len__alu8, ctx__pt->mode_specific__u.eax.nonce__bu8));
    FLEA_CCALL(THR_flea_ae__compute_omac_indexed(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, 1, block_len__alu8, header__pcu8, header_len__dtl, ctx__pt->mode_specific__u.eax.header_omac__bu8));
    // correct the nonce of the counter-mode-context:
    memcpy(ctx__pt->mode_specific__u.eax.ctr_ctx__t.ctr_block__bu8, ctx__pt->mode_specific__u.eax.nonce__bu8, block_len__alu8);
    // now start the ciphertext MAC computation
    FLEA_CCALL(THR_flea_ae__compute_omac_indexed(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, 2, block_len__alu8, NULL, 0, NULL));

  }
  FLEA_THR_FIN_SEC_empty();

}

flea_err_t THR_flea_ae_ctx_t__update_encryption (flea_ae_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8, flea_dtl_t input_output_len__dtl )
{

  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_ctx_t__crypt(&ctx__pt->mode_specific__u.eax.ctr_ctx__t, input__pcu8, output__pu8, input_output_len__dtl);
  FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, output__pu8, input_output_len__dtl));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ae__encrypt (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* header__pcu8, flea_dtl_t header_len__dtl, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8, flea_dtl_t input_output_len__dtl, flea_u8_t* tag__pu8, flea_al_u8_t tag_len__alu8)
{
  flea_ae_ctx_t ctx__t = flea_ae_ctx_t__INIT_VALUE;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, header__pcu8, header_len__dtl, tag_len__alu8));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_encryption(&ctx__t, input__pcu8, output__pu8, input_output_len__dtl));
  FLEA_CCALL(THR_flea_ae_ctx_t__final_encryption(&ctx__t, tag__pu8, &tag_len__alu8));
  FLEA_THR_FIN_SEC(
    flea_ae_ctx_t__dtor(&ctx__t);
    );
}
flea_err_t THR_flea_ae__decrypt (flea_ae_id_t id__t, const flea_u8_t* key__pcu8, flea_dtl_t key_len__dtl, const flea_u8_t* nonce__pcu8, flea_dtl_t nonce_len__dtl, const flea_u8_t* header__pcu8, flea_dtl_t header_len__dtl, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8, flea_dtl_t input_output_len__dtl, const flea_u8_t* tag__pcu8, flea_al_u8_t tag_len__alu8)
{
  flea_ae_ctx_t ctx__t = flea_ae_ctx_t__INIT_VALUE;
  flea_dtl_t output_len__dtl = input_output_len__dtl;

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ae_ctx_t__ctor(&ctx__t, id__t, key__pcu8, key_len__dtl, nonce__pcu8, nonce_len__dtl, header__pcu8, header_len__dtl, tag_len__alu8));
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&ctx__t, input__pcu8, input_output_len__dtl, output__pu8, &output_len__dtl));
  output__pu8 += output_len__dtl;
  output_len__dtl = input_output_len__dtl - output_len__dtl;
  FLEA_CCALL(THR_flea_ae_ctx_t__update_decryption(&ctx__t, tag__pcu8, tag_len__alu8, output__pu8, &output_len__dtl));
  FLEA_CCALL(THR_flea_ae_ctx_t__final_decryption(&ctx__t));
  FLEA_THR_FIN_SEC(
    flea_ae_ctx_t__dtor(&ctx__t);
    );
}

flea_err_t THR_flea_ae_ctx_t__update_decryption (flea_ae_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_dtl_t input_len__dtl, flea_u8_t* output__pu8, flea_dtl_t* output_len__pdtl )
{
  flea_al_u8_t tag_len__alu8 = ctx__pt->tag_len__u8;
  flea_al_u8_t pending__alu8 = ctx__pt->mode_specific__u.eax.pending__u8;
  flea_u8_t* pend_buffer__pu8 = ctx__pt->mode_specific__u.eax.buffer__bu8;

  FLEA_THR_BEG_FUNC();

  if(pending__alu8 < tag_len__alu8)
  {
    flea_al_u8_t to_append__alu8;
    flea_al_u8_t free__alu8 = tag_len__alu8 - pending__alu8;
    to_append__alu8 = FLEA_MIN(input_len__dtl, free__alu8);
    memcpy(pend_buffer__pu8 + pending__alu8, input__pcu8, to_append__alu8);
    input__pcu8 += to_append__alu8;
    input_len__dtl -= to_append__alu8;
    ctx__pt->mode_specific__u.eax.pending__u8 = pending__alu8 + to_append__alu8;
  }
  if(*output_len__pdtl < input_len__dtl)
  {
    FLEA_THROW("error when updating EAX decryptor: output length insufficient", FLEA_ERR_BUFF_TOO_SMALL);
  }
  *output_len__pdtl = 0;
  if(input_len__dtl >= tag_len__alu8) // implies that the pending buffer is full
  {
    flea_dtl_t process_len__dtl = input_len__dtl - tag_len__alu8;
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, pend_buffer__pu8, tag_len__alu8));
    flea_ctr_mode_ctx_t__crypt(&ctx__pt->mode_specific__u.eax.ctr_ctx__t, pend_buffer__pu8, output__pu8, tag_len__alu8);
    *output_len__pdtl = tag_len__alu8;
    output__pu8 += tag_len__alu8;
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, input__pcu8, process_len__dtl));
    flea_ctr_mode_ctx_t__crypt(&ctx__pt->mode_specific__u.eax.ctr_ctx__t, input__pcu8, output__pu8, process_len__dtl);
    *output_len__pdtl +=  process_len__dtl;
    input_len__dtl -= process_len__dtl;
    input__pcu8 += process_len__dtl;
  }
  else // does nothing if input_len__dtl = 0
  {
    // only a part of the pending buffer may be processed and replaced by new
    // input
    flea_al_u8_t remaining__alu8  = tag_len__alu8 - input_len__dtl;
    FLEA_CCALL(THR_flea_mac_ctx_t__update(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, pend_buffer__pu8, input_len__dtl));
    flea_ctr_mode_ctx_t__crypt(&ctx__pt->mode_specific__u.eax.ctr_ctx__t, pend_buffer__pu8, output__pu8, input_len__dtl);
    *output_len__pdtl = input_len__dtl;
    memmove(pend_buffer__pu8, pend_buffer__pu8 + input_len__dtl, remaining__alu8);
    memcpy(pend_buffer__pu8 + remaining__alu8, input__pcu8, input_len__dtl);
    input_len__dtl = 0;
  }
  if(input_len__dtl)
  {
    memcpy(pend_buffer__pu8, input__pcu8, tag_len__alu8);
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ae_ctx_t__final_encryption (flea_ae_ctx_t* ctx__pt, flea_u8_t* tag__pu8, flea_al_u8_t* tag_len__palu8)
{
  FLEA_THR_BEG_FUNC();
  if(*tag_len__palu8 < ctx__pt->tag_len__u8)
  {
    FLEA_THROW("output buffer for tag too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
  FLEA_CCALL(THR_flea_mac_ctx_t__final_compute(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, tag__pu8, tag_len__palu8)); // last arg only dummy, might be reduced to correct output size
  flea__xor_bytes_in_place(tag__pu8, ctx__pt->mode_specific__u.eax.header_omac__bu8, *tag_len__palu8);
  flea__xor_bytes_in_place(tag__pu8, ctx__pt->mode_specific__u.eax.nonce__bu8, *tag_len__palu8);

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_ae_ctx_t__final_decryption (flea_ae_ctx_t* ctx__pt)
{
  flea_al_u8_t tag_len__alu8 = ctx__pt->tag_len__u8;

  FLEA_THR_BEG_FUNC();

  if(ctx__pt->mode_specific__u.eax.pending__u8 != tag_len__alu8)
  {
    FLEA_THROW("not enough data fed into EAX decryptor", FLEA_ERR_INV_STATE);
  }
  flea__xor_bytes_in_place(ctx__pt->mode_specific__u.eax.buffer__bu8, ctx__pt->mode_specific__u.eax.header_omac__bu8, tag_len__alu8);
  flea__xor_bytes_in_place(ctx__pt->mode_specific__u.eax.buffer__bu8, ctx__pt->mode_specific__u.eax.nonce__bu8, tag_len__alu8);
  FLEA_CCALL(THR_flea_mac_ctx_t__final_verify(&ctx__pt->mode_specific__u.eax.cmac_ctx__t, ctx__pt->mode_specific__u.eax.buffer__bu8, tag_len__alu8));
  FLEA_THR_FIN_SEC_empty();
}

void flea_ae_ctx_t__dtor (flea_ae_ctx_t* ctx__pt)
{
  if(ctx__pt->tag_len__u8 == 0)
  {
    return;
  }
  if(ctx__pt->config__pt->ae_mode__t == eax)
  {
    flea_mac_ctx_t__dtor_cipher_ctx_ref(&ctx__pt->mode_specific__u.eax.cmac_ctx__t);
    flea_ctr_mode_ctx_t__dtor(&ctx__pt->mode_specific__u.eax.ctr_ctx__t);
#ifdef FLEA_USE_HEAP_BUF
    FLEA_FREE_MEM_CHK_SET_NULL(ctx__pt->mode_specific__u.eax.nonce__bu8);
    FLEA_FREE_MEM_CHK_SET_NULL(ctx__pt->mode_specific__u.eax.header_omac__bu8);
    FLEA_FREE_MEM_CHK_SET_NULL(ctx__pt->mode_specific__u.eax.buffer__bu8); // not secret, only used to buffer ciphertext
#endif
  }
}
#endif // #ifdef FLEA_HAVE_AE
