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


#ifndef _flea_mac__H_
#define _flea_mac__H_


#include "internal/common/default.h"
#include "flea/block_cipher.h"
#include "flea/hash.h"
#include "internal/common/mac_int.h"

#ifdef __cplusplus
extern "C" {
#endif



/**
 * Supported MAC algorithms
 */
typedef enum { flea_hmac_md5, flea_hmac_sha1, flea_hmac_sha224, flea_hmac_sha256, flea_hmac_sha384, flea_hmac_sha512, flea_cmac_des, flea_cmac_tdes_2key, flea_cmac_tdes_3key, flea_cmac_aes128, flea_cmac_aes192, flea_cmac_aes256 } flea_mac_id_t;

/**
 * MAC context type
 */
struct struct_flea_mac_ctx_t
{
  flea_u8_t output_len__u8;
  flea_mac_mode_id_t mode_id__t;
  union
  {
    flea_mac_ctx_hmac_specific_t hmac_specific__t;
    flea_mac_ctx_cmac_specific_t cmac_specific__t;
  } primitive_specific_ctx__u;

};

#define flea_mac_ctx_t__INIT_VALUE { .output_len__u8 = 0 }

#ifdef FLEA_USE_HEAP_BUF
#define flea_mac_ctx_t__INIT(__a) do { (__a)->output_len__u8 = 0; } while(0)
#else
#define flea_mac_ctx_t__INIT(__a) do { (__a)->output_len__u8 = 0; } while(0)

#endif


/**
 * Create a MAC context object for either MAC computation of verification.
 *
 * @param ctx pointer to the context object to create
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the MAC key to use
 * @param key_len length of key
 *
 * @return flea error code
 */
flea_err_t THR_flea_mac_ctx_t__ctor(flea_mac_ctx_t* ctx, flea_mac_id_t id, const flea_u8_t* key, flea_al_u16_t key_len);

/**
 * Destroy a MAC object.
 *
 * @param ctx pointer to the context object to destroy
 *
 */
void flea_mac_ctx_t__dtor(flea_mac_ctx_t* ctx);

/**
 * Feed data to a MAC object for either MAC computation of verification.
 *
 * @param ctx pointer to the context object to use
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 *
 * @return flea error code
 */
flea_err_t THR_flea_mac_ctx_t__update(flea_mac_ctx_t* ctx, const flea_u8_t* dta, flea_dtl_t data_len);

/**
 * Finalize a MAC computation.
 *
 * @param ctx pointer to the context object to use
 * @param result pointer to the memory area where to store the MAC value
 * @param result_len the caller must provide a pointer to a value representing
 * the available length of result, upon function return this value will be
 * updated to the number of bytes written to result
 *
 * @return flea error code
 */
flea_err_t THR_flea_mac_ctx_t__final_compute(flea_mac_ctx_t* ctx, flea_u8_t* result, flea_al_u8_t* result_len);

/**
 * Finalize MAC verification.
 *
 * @param ctx pointer to the context object to use
 * @param mac pointer to the MAC value to be verified
 * @param mac_len the length of mac
 *
 * @return flea error code: FLEA_ERR_FINE if the verification succeeded,
 * FLEA_ERR_INV_MAC if it failed
 */
flea_err_t THR_flea_mac_ctx_t__final_verify(flea_mac_ctx_t* ctx, const flea_u8_t* mac, flea_al_u8_t mac_len);

/**
 * Compute a MAC over a data string.
 *
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the key to use
 * @param key_len length of key
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 * @param result pointer to the memory area where to store the MAC value
 * @param result_len the caller must provide a pointer to a value representing
 * the available length of result, upon function return this value will be
 * updated to the number of bytes written to result
 *
 * @return flea error code
 */
flea_err_t THR_flea_mac__compute_mac(flea_mac_mode_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, const flea_u8_t* dta, flea_dtl_t dta_len, flea_u8_t* result, flea_al_u8_t* result_len);

/**
 * Verify a MAC over a data string.
 *
 * @param id the ID of the MAC algorithm to use
 * @param key pointer to the key to use
 * @param key_len length of key
 * @param dta pointer to the data to be authenticated
 * @param dta_len length of dta
 * @param mac pointer to the MAC value to be verified
 * @param mac_len the length of mac
 *
 * @return flea error code: FLEA_ERR_FINE if the verification succeeded, FLEA_ERR_INV_MAC if it failed
 */
flea_err_t THR_flea_mac__verify_mac(flea_mac_mode_id_t id, const flea_u8_t* key, flea_al_u16_t key_len, const flea_u8_t* dta, flea_dtl_t dta_len, const flea_u8_t* mac, flea_al_u8_t mac_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
