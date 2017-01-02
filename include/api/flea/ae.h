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


#ifndef _flea_ae__H_
#define _flea_ae__H_

#include "flea/block_cipher.h"
#include "flea/mac.h"
#include "internal/common/ae_int.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Available AE modes.
 */
typedef enum { flea_eax_aes128, flea_eax_aes192, flea_eax_aes256 } flea_ae_id_t;


/**
 * AE context object.
 */
typedef struct
{
  flea_u8_t tag_len__u8;
  const flea_ae_config_entry_t* config__pt;
  union
  {
    flea_ae_eax_specific_t eax;
  } mode_specific__u;

}flea_ae_ctx_t;

#define flea_ae_ctx_t__INIT_VALUE  { .tag_len__u8 = 0 }


/**
 * Create an AE context. The context can be used for either encryption or
 * decryption by using the respective functions.
 *
 * @param ctx__pt pointer to the context object to create
 * @param id__t the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param tag_len the desired length of the tag in bytes. may be smaller than
 * the chosen scheme's natural tag length. in that case, the scheme operates
 * with truncated tags
 *
 * @return flea error code
 * */
flea_err_t THR_flea_ae_ctx_t__ctor(flea_ae_ctx_t* ctx, flea_ae_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, const flea_u8_t* nonce, flea_al_u8_t nonce_len, const flea_u8_t* header, flea_dtl_t header_len, flea_al_u8_t tag_len);

/**
 * Destroy an AE context object.
 *
 * @param ctx pointer to the object to destroy
 */
void flea_ae_ctx_t__dtor(flea_ae_ctx_t* ctx);

/**
 * Feed a ctx with plaintext data and produce ciphertext output. The function
 * writes the same number of bytes of ciphertext as the plaintext input.
 *
 * @param ctx the AE context to use
 * @param input pointer to the plaintext bytes
 * @param output pointer to the location where the ciphertext shall be output
 * @param length of input and output in bytes
 *
 * @return flea error code
 */
flea_err_t THR_flea_ae_ctx_t__update_encryption(flea_ae_ctx_t* ctx, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len);

/**
 * Finalize an AE encryption operation. The number of bytes written to tag is
 * equal to the length of tag_len in the call to THR_flea_ae_ctx_t__ctor
 *
 * @param ctx the AE context to use
 * @param tag memory location where to store the generated AE tag
 * @param length of tag (used to detect the case where tag_len is too small)
 *
 * @return flea error code
 */
flea_err_t THR_flea_ae_ctx_t__final_encryption(flea_ae_ctx_t* ctx, flea_u8_t* tag, flea_al_u8_t* tag_len);

/**
 * Feed an AE ctx with ciphertext data for decryption. The number of bytes
 * output may differ from the input length. This is due to the fact that the
 * last part of the input data is expected to be the AE tag. Accordingly, the
 * algorithm has to buffer the final block within each call to this function,
 * since that will be the tag if not more data follows.
 *
 * @param ctx the AE context to use
 * @param input the ciphertext input data
 * @param length of the ciphertext input data
 * @param output pointer to the memory location where to store the output
 * @param length of the memory location where to store the output
 *
 * @return flea error code
 */
flea_err_t THR_flea_ae_ctx_t__update_decryption(flea_ae_ctx_t* ctx, const flea_u8_t* input, flea_dtl_t input_len, flea_u8_t* output, flea_dtl_t* output_len);

/**
 * Finalize the decryption operation. All plaintext has already been output by
 * previous calls to THR_flea_ae_ctx_t__update_decryption. This function
 * generates the tag value based on the input data and verifies it against the
 * AE tag which was provided as the last part of the input data in the last call
 * to THR_flea_ae_ctx_t__update_decryption.
 *
 * @param ctx the AE context to use

 * @return flea error code. If the MAC verification failed, FLEA_ERR_INV_MAC is
 * returned. if it succeeded, FLEA_ERR_FINE is returned.
 *
 */
flea_err_t THR_flea_ae_ctx_t__final_decryption(flea_ae_ctx_t* ctx__pt);

/**
 * Encrypt a complete plaintext using an AE scheme.
 *
 * @param id the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param input the plaintext
 * @param output the ciphertext
 * @param input_output_len the length of input and output
 * @param tag pointer to the memory location where to write the AE tag
 * @param tag_len desired length of the tag
 *
 * @return flea error code
 */
flea_err_t THR_flea_ae__encrypt(flea_ae_id_t id, const flea_u8_t* key, flea_dtl_t key_len, const flea_u8_t* nonce, flea_dtl_t nonce_len, const flea_u8_t* header, flea_dtl_t header_len, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len, flea_u8_t* tag, flea_al_u8_t tag_len);

/**
 * Decrypt a complete plaintext using an AE scheme.
 *
 * @param id the id of the AE scheme to use
 * @param key pointer to the key bytes
 * @param key_len number of key bytes
 * @param nonce pointer to the nonce bytes
 * @param nonce_len number of nonce bytes
 * @param header pointer to the header, i.e. associated data ( not part of the
 * ciphertext)
 * @param header_len length of the header in bytes
 * @param input the ciphertext
 * @param output the plaintext
 * @param input_output_len the length of input and output
 * @param tag pointer to the memory location where the tag is stored, e.g. at
 * the end of ciphertext.
 * @param tag_len length of the tag
 *
 * @return flea error code. If the MAC verification failed, FLEA_ERR_INV_MAC is
 * returned. if it succeeded, FLEA_ERR_FINE is returned.
 */
flea_err_t THR_flea_ae__decrypt(flea_ae_id_t id, const flea_u8_t* key, flea_dtl_t key_len, const flea_u8_t* nonce, flea_dtl_t nonce_len, const flea_u8_t* header, flea_dtl_t header_len, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len, const flea_u8_t* tag, flea_al_u8_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
