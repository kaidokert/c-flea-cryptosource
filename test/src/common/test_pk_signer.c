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
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "internal/common/math/curve_gfp.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/ecdsa.h"
#include "internal/common/math/point_gfp.h"
#include "flea/algo_config.h"
#include "flea/ec_key_gen.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/pk_api.h"
#include "test_data_rsa_key_internal_format.h"

#ifdef FLEA_HAVE_ASYM_SIG
static flea_err_t THR_flea_test_pk_signer_init_dtor ()
{
  FLEA_DECL_OBJ(ctx__t, flea_pk_signer_t);
  FLEA_THR_BEG_FUNC();
  flea_pk_signer_t ctx2__t;
  flea_pk_signer_t__INIT(&ctx2__t);

  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&ctx__t);
    flea_pk_signer_t__dtor(&ctx2__t);
    );
}
#endif // #ifdef FLEA_HAVE_ASYM_SIG

#if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 && defined FLEA_HAVE_SHA384_512
static flea_err_t THR_flea_test_pkcs1_v1_5_signature_reference ()
{
  // botan reference value
  const flea_u8_t signature__acu8[] =
  { 0x90, 0xBC, 0xD2, 0x89, 0xBE, 0x5A, 0x8A, 0x33, 0x92, 0x15, 0xE5, 0xB2, 0x83, 0x78, 0x63, 0x04, 0x41, 0xE0, 0x1E, 0x98, 0x05, 0x87, 0x57, 0x6D, 0x80, 0xA2, 0xBD, 0xE9, 0x8E, 0x78, 0x2C, 0xE1, 0xC7, 0x3C, 0x40, 0x7E, 0xE6, 0xBA, 0x84, 0x08, 0xB3, 0xFE, 0xDE, 0xBB, 0x91, 0xFC, 0xDD, 0x73, 0xF1, 0xE3, 0x88, 0x05, 0x7B, 0x6A, 0xE5, 0x6E, 0xC0, 0x2F, 0x8E, 0xDF, 0x50, 0x22, 0x97, 0x57, 0xDC, 0x27, 0xD0, 0xBF, 0x4E, 0xFB, 0x13, 0x27, 0xF8, 0xA4, 0xBE, 0xA9, 0x73, 0xA4, 0xDC, 0x3A, 0x79, 0xF5, 0xF0, 0xC1, 0x3C, 0xE0, 0x4F, 0xAD, 0x25, 0x88, 0x5F, 0xB0, 0x84, 0x0E, 0xCD, 0xDB, 0xC5, 0xE5, 0xD3, 0x01, 0x12, 0xAB, 0xB8, 0x78, 0x85, 0x33, 0x28, 0xF8, 0x6D, 0x50, 0x77, 0x4D, 0xDB, 0x1A, 0x31, 0x82, 0x74, 0x34, 0xA0, 0xD9, 0x41, 0x63, 0xE2, 0x2E, 0xD6, 0x1C, 0x7E, 0x74, 0x76, 0x6B, 0x21, 0x88, 0x9F, 0x1F, 0xD6, 0xD4, 0xCF, 0xA0, 0x27, 0x27, 0xD2, 0xD0, 0xEB, 0x0E, 0x82, 0x3D, 0x6F, 0xD1, 0xFE, 0x00, 0x1A, 0x3B, 0xC4, 0x72, 0x91, 0x16, 0xA9, 0x55, 0x7F, 0xE2, 0x50, 0x1F, 0x41, 0x7F, 0x0F, 0xE8, 0xEA, 0x3F, 0x0A, 0x10, 0xCC, 0x04, 0x5E, 0x5F, 0x95, 0x65, 0x9B, 0xF2, 0xF4, 0x45, 0xB1, 0x1C, 0x20, 0x58, 0x4C, 0xCE, 0x13, 0x35, 0xDB, 0xB5, 0x5B, 0x95, 0x5F, 0xC3, 0x73, 0x9D, 0xA8, 0xE1, 0x86, 0xB1, 0xEB, 0x6F, 0xDD, 0x4B, 0xE5, 0x97, 0x7A, 0x1A, 0x55, 0x42, 0x00, 0xF5, 0x09, 0x6B, 0xAD, 0x2A, 0x96, 0x5D, 0x05, 0x4D, 0xD8, 0xDF, 0xEB, 0x2A, 0xDC, 0xAE, 0xFB, 0x5D, 0x93, 0x5C, 0xE3, 0x75, 0x37, 0x80, 0x16, 0x55, 0x35, 0xC5, 0x1B, 0x79, 0x8C, 0x69, 0xB3, 0x03, 0xB8, 0xAA, 0xCF, 0xDA, 0xF8, 0x7D, 0x11, 0xDA, 0x4C, 0x10, 0xDE, 0x73 };
  const flea_u8_t message__acu8[] = "abc";

  const flea_u8_t rsa_pub_exp__acu8[] = { 0x01, 0x00, 0x01 };

  FLEA_DECL_OBJ(verifier__t, flea_pk_signer_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&verifier__t, flea_sha384));
  FLEA_CCALL(THR_flea_pk_signer_t__update(&verifier__t, message__acu8, sizeof(message__acu8)));
  FLEA_CCALL(THR_flea_pk_signer_t__final_verify(&verifier__t, flea_rsa_pkcs1_v1_5_sign, rsa_2048_pub_key_internal_format__acu8, sizeof(rsa_2048_pub_key_internal_format__acu8), rsa_pub_exp__acu8, sizeof(rsa_pub_exp__acu8), signature__acu8, sizeof(signature__acu8)));
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&verifier__t);
    );
}
#endif // #if defined FLEA_HAVE_RSA && FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 && defined FLEA_HAVE_SHA384_512


#if defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_RSA
static flea_err_t THR_flea_test_pk_signer_sign_verify_inner (flea_pk_scheme_id_t scheme_id__t, flea_hash_id_t hash_id__t, const flea_u8_t* param__pc_u8, flea_al_u16_t param_len__al_u16)
{
  flea_al_u8_t is_ecdsa = param__pc_u8 != NULL;

  FLEA_DECL_OBJ(signer__t, flea_pk_signer_t);
  FLEA_DECL_OBJ(verifier__t, flea_pk_signer_t);
  FLEA_DECL_OBJ(verifier2__t, flea_pk_signer_t);
  FLEA_DECL_BUF(sig_buf__b_u8, flea_u8_t, FLEA_PK_MAX_SIGNATURE_LEN);
  FLEA_DECL_BUF(pub_key__b_u8, flea_u8_t, FLEA_PK_MAX_PUBKEY_LEN);
  FLEA_DECL_BUF(priv_key__b_u8, flea_u8_t, FLEA_ECC_MAX_PUBKEY_LEN );  // only used ECDSA, not for RSA
  const flea_u8_t* priv_key_alias__p_u8;
  const flea_u8_t* pub_key_alias__p_u8;
  flea_al_u16_t sig_len__al_u16;
  flea_al_u16_t pub_key_len__al_u16;
  flea_al_u8_t pub_key_len__al_u8;
  flea_al_u16_t priv_key_len__al_u16;
  flea_al_u8_t priv_key_len__al_u8;
  flea_u8_t i_u8;
  const flea_u8_t rsa_pub_exp__a_u8[] = { 0x01, 0x00, 0x01 };
  FLEA_THR_BEG_FUNC();

  pub_key_len__al_u16 = FLEA_PK_MAX_PUBKEY_LEN;
  priv_key_len__al_u16 = FLEA_PK_MAX_PRIVKEY_LEN;
  sig_len__al_u16 = FLEA_PK_MAX_SIGNATURE_LEN;

  FLEA_ALLOC_BUF(sig_buf__b_u8, sig_len__al_u16);

  pub_key_len__al_u8 = pub_key_len__al_u16;
  priv_key_len__al_u8 = pub_key_len__al_u16;
  if(param__pc_u8)
  {

    FLEA_ALLOC_BUF(pub_key__b_u8, pub_key_len__al_u16);
    FLEA_ALLOC_BUF(priv_key__b_u8, priv_key_len__al_u16);
#ifdef FLEA_HAVE_ECC
    FLEA_CCALL(THR_flea_generate_ecc_key(pub_key__b_u8, &pub_key_len__al_u8, priv_key__b_u8, &priv_key_len__al_u8, param__pc_u8));
#endif
    priv_key_alias__p_u8 = priv_key__b_u8;
    pub_key_alias__p_u8 = pub_key__b_u8;

    priv_key_len__al_u16 = priv_key_len__al_u8;
    pub_key_len__al_u16 = pub_key_len__al_u8;
  }
  else
  {
    // it's an RSA key
    param__pc_u8 = rsa_pub_exp__a_u8;
    priv_key_alias__p_u8 = rsa_2048_crt_key_internal_format__acu8;
    param_len__al_u16 = sizeof(rsa_pub_exp__a_u8);
    priv_key_len__al_u16 = sizeof(rsa_2048_crt_key_internal_format__acu8);
    pub_key_alias__p_u8 = rsa_2048_pub_key_internal_format__acu8;
    pub_key_len__al_u16 = sizeof(rsa_2048_pub_key_internal_format__acu8);
  }
//#ifdef FLEA_USE_HEAP_BUF
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&signer__t, hash_id__t));
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&verifier__t, hash_id__t));
  FLEA_CCALL(THR_flea_pk_signer_t__ctor(&verifier2__t, hash_id__t));
/*#else
   #error test not implemented for stack version
 #endif */
  for(i_u8 = 0; i_u8 < 255; i_u8++)
  {

    FLEA_CCALL(THR_flea_pk_signer_t__update(&verifier__t, &i_u8, 1));
    if(i_u8 != 0)
    {
      FLEA_CCALL(THR_flea_pk_signer_t__update(&verifier2__t, &i_u8, 1));
    }
    FLEA_CCALL(THR_flea_pk_signer_t__update(&signer__t, &i_u8, 1));
  }
  FLEA_CCALL(THR_flea_pk_signer_t__final_sign(&signer__t, scheme_id__t, priv_key_alias__p_u8, priv_key_len__al_u16, param__pc_u8, param_len__al_u16, sig_buf__b_u8, &sig_len__al_u16));


  if(is_ecdsa)
  {
    // ecdsa processing
    FLEA_CCALL(THR_flea_pk_signer_t__final_verify(&verifier__t, scheme_id__t, pub_key_alias__p_u8, pub_key_len__al_u16, param__pc_u8, param_len__al_u16, sig_buf__b_u8, sig_len__al_u16));

    if(FLEA_ERR_INV_SIGNATURE != THR_flea_pk_signer_t__final_verify(&verifier2__t, scheme_id__t, pub_key_alias__p_u8, pub_key_len__al_u16, param__pc_u8, param_len__al_u16, sig_buf__b_u8, sig_len__al_u16))
    {
      FLEA_THROW("error with invalid signature", FLEA_ERR_FAILED_TEST);
    }
  }
  else
  {
    // rsa processing

    FLEA_CCALL(THR_flea_pk_signer_t__final_verify(&verifier__t, scheme_id__t, pub_key_alias__p_u8, pub_key_len__al_u16, rsa_pub_exp__a_u8, sizeof(rsa_pub_exp__a_u8), sig_buf__b_u8, sig_len__al_u16));

    if(FLEA_ERR_INV_SIGNATURE != THR_flea_pk_signer_t__final_verify(&verifier2__t, scheme_id__t, pub_key_alias__p_u8, pub_key_len__al_u16,  rsa_pub_exp__a_u8, sizeof(rsa_pub_exp__a_u8), sig_buf__b_u8, sig_len__al_u16))
    {
      FLEA_THROW("error with invalid signature", FLEA_ERR_FAILED_TEST);
    }
  }
  FLEA_THR_FIN_SEC(
    flea_pk_signer_t__dtor(&signer__t);
    flea_pk_signer_t__dtor(&verifier__t);
    flea_pk_signer_t__dtor(&verifier2__t);
    FLEA_FREE_BUF_FINAL(sig_buf__b_u8);
    FLEA_FREE_BUF_FINAL(pub_key__b_u8);
    FLEA_FREE_BUF_FINAL(priv_key__b_u8);
    );
}
#endif // #if defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_RSA

flea_err_t THR_flea_test_pk_signer_sign_verify ()
{
#ifdef FLEA_HAVE_ECDSA
  const flea_u8_t* dp__pt = flea_ec_dom_par__get_predefined_dp_ptr(flea_brainpoolP224r1);
#endif
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_ECDSA
  if(dp__pt == NULL)
  {
#if FLEA_ECC_MAX_MOD_BIT_SIZE < 224
    // nothing to do
#else
    FLEA_THROW("ec dp not found", FLEA_ERR_FAILED_TEST);
#endif
  }
  else
  {
    FLEA_CCALL(THR_flea_test_pk_signer_sign_verify_inner(flea_ecdsa_emsa1, flea_sha224, dp__pt, flea_ec_dom_par__get_predefined_dp_len(flea_brainpoolP224r1)));
  }
#endif
#ifdef FLEA_HAVE_RSA
#   if FLEA_RSA_MAX_KEY_BIT_SIZE < 2048
  flea_err_t err_code = THR_flea_test_pk_signer_sign_verify_inner(flea_rsa_pkcs1_v1_5_sign, flea_sha256, NULL, 0);
  if(err_code != FLEA_ERR_INV_KEY_SIZE && err_code != FLEA_ERR_BUFF_TOO_SMALL )
  {
    FLEA_THROW("wrong return value for invalid key size", FLEA_ERR_FAILED_TEST);
  }
#   else
  FLEA_CCALL(THR_flea_test_pk_signer_sign_verify_inner(flea_rsa_pkcs1_v1_5_sign, flea_sha256, NULL, 0));
#     ifdef FLEA_HAVE_SHA384_512
  FLEA_CCALL(THR_flea_test_pkcs1_v1_5_signature_reference());
#     endif
#   endif
#endif

#ifdef FLEA_HAVE_ASYM_SIG
  FLEA_CCALL(THR_flea_test_pk_signer_init_dtor());
#endif 
  FLEA_THR_FIN_SEC_empty();
}
