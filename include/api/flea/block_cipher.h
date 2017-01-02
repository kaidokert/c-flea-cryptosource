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


#ifndef _flea_block_cipher__H_
#define _flea_block_cipher__H_

#include "internal/common/default.h"
#include "flea/types.h"
#include "internal/common/block_cipher/block_cipher_int.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH 16

/**
 * General cipher prossing direction.
 */
typedef enum { flea_encrypt, flea_decrypt } flea_cipher_dir_t;

/* fwd declaration */
/*struct struct_flea_ecb_mode_ctx_t;
   typedef struct struct_flea_ecb_mode_ctx_t flea_ecb_mode_ctx_t;*/


/**
 * Block cipher context type.
 */
struct struct_flea_ecb_mode_ctx_t
{
  const flea_block_cipher_config_entry_t* config__pt;
  flea_u8_t key_byte_size__u8;
  flea_u8_t block_length__u8;
  flea_u8_t nb_rounds__u8;
  flea_cipher_dir_t dir__t;
#ifdef FLEA_USE_HEAP_BUF
  flea_u32_t * expanded_key__bu8;
#elif defined FLEA_USE_STACK_BUF
  flea_u32_t expanded_key__bu8 [FLEA_BLOCK_CIPHER_MAX_EXPANDED_KEY_U32_SIZE];
#else
#error MUST DEFINE HEAP OR STACK USAGE FOR FLEA
#endif
  flea_cipher_block_processing_f block_crypt_f;
};



typedef struct
{
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* ctr_block__bu8;
  flea_u8_t* pending_mask__bu8;
#else
  flea_u8_t ctr_block__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t pending_mask__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
  flea_al_u8_t pending_offset__alu8;
  const flea_block_cipher_config_entry_t* config__pt;
  flea_ecb_mode_ctx_t cipher_ctx__t;
} flea_ctr_mode_ctx_t;


typedef struct
{
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* iv__bu8;
#else
  flea_u8_t iv__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif
  flea_ecb_mode_ctx_t cipher_ctx__t;
} flea_cbc_mode_ctx_t;


#ifdef FLEA_USE_HEAP_BUF
#define flea_ecb_mode_ctx_t__INIT(__p) do { (__p)->expanded_key__bu8 = NULL; (__p)->config__pt = NULL; } while(0)
#define flea_ctr_mode_ctx_t__INIT(__p) do { (__p)->ctr_block__bu8 = NULL; (__p)->pending_mask__bu8 = NULL; flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); } while(0)
#define flea_cbc_mode_ctx_t__INIT(__p) do { (__p)->iv__bu8 = NULL; flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); } while(0)
#define flea_ecb_mode_ctx_t__INIT_VALUE  { .expanded_key__bu8 = NULL, .config__pt = NULL }
#define flea_ctr_mode_ctx_t__INIT_VALUE { .ctr_block__bu8 = NULL, .pending_mask__bu8 = NULL, .cipher_ctx__t = flea_ecb_mode_ctx_t__INIT_VALUE  }
#define flea_cbc_mode_ctx_t__INIT_VALUE { .iv__bu8 = NULL, .cipher_ctx__t = flea_ecb_mode_ctx_t__INIT_VALUE }
#else
#define flea_ecb_mode_ctx_t__INIT(__p) do { (__p)->config__pt = NULL; } while(0)
#define flea_ctr_mode_ctx_t__INIT(__p) do { flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); } while(0)
#define flea_cbc_mode_ctx_t__INIT(__p) do { flea_ecb_mode_ctx_t__INIT(&(__p)->cipher_ctx__t); } while(0)
#define flea_ecb_mode_ctx_t__INIT_VALUE  { .config__pt = NULL }
#define flea_ctr_mode_ctx_t__INIT_VALUE { .cipher_ctx__t = flea_ecb_mode_ctx_t__INIT_VALUE  }
#define flea_cbc_mode_ctx_t__INIT_VALUE { .cipher_ctx__t = flea_ecb_mode_ctx_t__INIT_VALUE }
#endif

/**
 * Find out the block byte size of a given cipher.
 *
 * @param id the id of the block cipher
 *
 * @return the block byte size
 */
flea_al_u8_t flea_block_cipher__get_block_size(flea_block_cipher_id_t id);

/**
 * Find out the key byte size of a given cipher.
 *
 * @param id the id of the block cipher
 *
 * @return the key byte size
 */
flea_al_u8_t flea_block_cipher__get_key_size(flea_block_cipher_id_t id);

/**
 * Create an ECB mode context.
 *
 * @param ctx pointer to the context object to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 */
flea_err_t THR_flea_ecb_mode_ctx_t__ctor(flea_ecb_mode_ctx_t* ctx, flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, flea_cipher_dir_t dir);

/**
 * Destroy an ECB mode context.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_ecb_mode_ctx_t__dtor(flea_ecb_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt (depending on the dir argument provided in the creation of
 * ctx) data.
 *
 * @param ctx pointer to the context object to use
 * @param input the input data
 * @param output the output data, may be equal to input (in-place encryption/decryption)
 * @param input_output_len the length of input and output
 * input__pcu8 = output__pu8 is allowed
 */
flea_err_t THR_flea_ecb_mode_crypt_data(flea_ecb_mode_ctx_t* ctx, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len);

/**
 * Create a CTR mode context. Starts with a counter block formed by (nonce || 0...0),
 * where 0...0 indicates the counter field's intitial value. The counter will continue
 * incrementing even when it grows into the nonce area
 * Can be used for either encryption or decryption.
 *
 * @param ctx pointer to the context to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param nonce pointer to the nonce value
 * @param nonce_len length of nonce, may range from 0 to the underlying cipher's * block size in bytes
 */
flea_err_t THR_flea_ctr_mode_ctx_t__ctor(flea_ctr_mode_ctx_t* ctx, flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u8_t key_len, const flea_u8_t* nonce, flea_al_u8_t nonce_len );

/**
 * Destroy a CTR mode context object.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_ctr_mode_ctx_t__dtor(flea_ctr_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt data in counter mode (the counter mode operation for
 * encryption and decryption is exactly the same) using a context object.
 * The internal counter state in ctx is updated according to the amount of processed data.
 *
 * @param ctx pointer to the context object to use
 * @param input the input data
 * @param output the output data
 * @param input_output_len the length of input and output data
 */
void flea_ctr_mode_ctx_t__crypt(flea_ctr_mode_ctx_t* ctx, const flea_u8_t* input, flea_u8_t* ouput, flea_dtl_t input_output_len);

/**
 * Encrypt/decrypt data in counter mode without using a context object.
 * The counter starts at zero.

 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param nonce pointer to the nonce value
 * @param nonce_len length of nonce, may range from 0 to the underlying cipher's * block size in bytes
 * @param input the input data
 * @param output the output data
 * @param input_output_len the length of input and output data
 */
flea_err_t THR_flea_ctr_mode_crypt_data(flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, const flea_u8_t* nonce, flea_al_u8_t nonce_len, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len);

/**
 * Encrypt/decrypt data in counter mode without using a context object and
 * 32-bit nonce value.
 * The nonce is big endian encoded in the leading part of the counter block.
 * The counter starts at zero.

 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param nonce the nonce value
 * @param input the input data
 * @param output the output data
 * @param input_output_len the length of input and output data
 */
flea_err_t THR_flea_ctr_mode_crypt_data_short_nonce(flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, flea_u32_t nonce, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len);

/**
 * Create a CBC mode context object.
 *
 * @param ctx pointer to the context object to create
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 */
flea_err_t THR_flea_cbc_mode_ctx_t__ctor(flea_cbc_mode_ctx_t* ctx, flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u8_t key_len, const flea_u8_t* iv, flea_al_u8_t iv_len, flea_cipher_dir_t dir);

/**
 * Destroy a CBC mode context object.
 *
 * @param ctx pointer to the context object to destroy
 */
void flea_cbc_mode_ctx_t__dtor(flea_cbc_mode_ctx_t* ctx);

/**
 * Encrypt or decrypt (depending on the dir argument provided in the creation of
 * ctx) data in using a CBC mode context object.
 *
 * @param ctx pointer to the context object to use
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input
 * @param input_output_len the length of input and output
 */
flea_err_t THR_flea_cbc_mode_ctx_t__crypt(flea_cbc_mode_ctx_t* ctx, const flea_u8_t* input, flea_u8_t* output, flea_dtl_t input_output_len);

/**
 * Encrypt or decrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param dir cipher direction (either flea_encrypt or flea_decrypt)
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input
 * @param input_output_len the length of input and output
 */
flea_err_t THR_flea_cbc_mode__crypt_data(flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u8_t key_len, const flea_u8_t* iv, flea_al_u8_t iv_len, flea_cipher_dir_t dir, flea_u8_t* output, const flea_u8_t* input, flea_dtl_t input_output_len);

/**
 * Encrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input
 * @param input_output_len the length of input and output
 */
flea_err_t THR_flea_cbc_mode__encrypt_data(flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u8_t key_len, const flea_u8_t* iv, flea_al_u8_t iv_len, flea_u8_t* output, const flea_u8_t* input, flea_dtl_t input_output_len);

/**
 * Decrypt data in CBC mode without using a context object.
 *
 * @param id the id of the cipher to use
 * @param key pointer to the key
 * @param key_len length of key in bytes
 * @param iv the initialization vector to use
 * @param iv_len the length of iv
 * @param input pointer to the input data
 * @param output pointer to the output data, may be equal to input
 * @param input_output_len the length of input and output
 */
flea_err_t THR_flea_cbc_mode__decrypt_data(flea_block_cipher_id_t id, const flea_u8_t* key, flea_al_u8_t key_len, const flea_u8_t* iv, flea_al_u8_t iv_len, flea_u8_t* output, const flea_u8_t* input, flea_dtl_t input_output_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
