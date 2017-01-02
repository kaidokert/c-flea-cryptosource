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


#ifndef __flea_self_test_H_
#define __flea_self_test_H_

#include "flea/hash.h"

#ifndef __FLEA_DO_PREPROC_API_HDRS__
#include "flea/error.h"
#include "flea/types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_test_flea_types(void);


flea_err_t THR_flea_test_montgm_mul_comp_n_prime(void);

flea_err_t THR_flea_test_mpi_div(void);

flea_err_t THR_flea_test_montgm_mul(void);
flea_err_t THR_flea_test_montgm_mul_small(void);
flea_err_t THR_flea_test_montgm_mul_small2(void);

flea_err_t THR_flea_test_mpi_square(void);

flea_err_t THR_flea_test_mpi_mul(void);

//flea_err_t THR_flea_test_rsa(void);


flea_err_t THR_flea_test_mpi_subtract(void);
flea_err_t THR_flea_test_mpi_subtract_2(void);
flea_err_t THR_flea_test_mpi_subtract_3(void);

flea_err_t THR_flea_test_mpi_add(void);
flea_err_t THR_flea_test_mpi_add_2(void);

flea_err_t THR_flea_test_mpi_add_sign(void);

flea_err_t THR_flea_test_rsa_crt(void);

flea_err_t THR_flea_test_mpi_encode(void);

flea_err_t THR_flea_test_mpi_shift_left_small(void);

flea_err_t THR_flea_test_mpi_shift_right(void);

flea_err_t THR_flea_test_mpi_invert_odd_mod(void);
flea_err_t THR_flea_test_mpi_invert_odd_mod_2(void);

flea_err_t THR_flea_test_arithm(void);

flea_err_t THR_flea_test_ecc_point_gfp_add(void);
flea_err_t THR_flea_test_ecc_point_gfp_double(void);

flea_err_t THR_flea_test_ecc_point_gfp_mul(void);

flea_err_t THR_flea_test_ecdsa_raw_basic(void);
flea_err_t THR_flea_test_cvc_sig_ver(void);
flea_err_t THR_flea_test_ecka_raw_basic(void);

flea_err_t THR_flea_test_emsa1(void);

flea_err_t THR_flea_test_pkcs1_v1_5_encoding(void);

flea_err_t THR_flea_test_oaep(void);

flea_err_t THR_flea_test_pk_signer_sign_verify(void);

flea_err_t THR_test_enc_BE_bitlen();

flea_err_t THR_test_incr_enc_BE_int();

flea_err_t THR_flea_test_pk_encryption(void);
/**
 * PC test based on file with test vectors for CRT-RSA raw
 */
flea_err_t THR_flea_test_crt_rsa_raw_file_based(void);

/**
 * used by PC tests
 */
flea_err_t THR_flea_test_rsa_crt_inner(
    flea_mpi_ulen_t mod_byte_len,
    const flea_u8_t* exp_sig,
    const flea_u8_t* mess_arr,
    const flea_u8_t* p_arr,
    flea_mpi_ulen_t p_len,
    const flea_u8_t* q_arr,
    flea_mpi_ulen_t q_len,
    const flea_u8_t* d1_arr,
    flea_mpi_ulen_t d1_len,
    const flea_u8_t* d2_arr,
    flea_mpi_ulen_t d2_len,
    const flea_u8_t* c_arr,
    flea_mpi_ulen_t c_len,
    //const flea_u8_t* pub_exp_arr,
    const flea_u8_t* mod_arr
  );

flea_err_t THR_flea_test_sha256_file_based();

flea_err_t THR_flea_test_hash_function_inner(
    const flea_u8_t* message,
    flea_u16_t message_len,
    const flea_u8_t* expected_digest,
    flea_u16_t expected_digest_len, 
    flea_hash_id_t id
    );

flea_err_t THR_flea_test_cipher_block_encr_decr(void);

//flea_err_t THR_flea_test_des(void);

flea_err_t THR_flea_test_sha256_update(void);

flea_err_t THR_flea_test_hash(void);

flea_err_t THR_flea_test_davies_meyer_aes128_hash_hash(void);

flea_err_t THR_flea_test_mac(void);

flea_err_t THR_flea_test_ae(void);

flea_err_t THR_flea_test_cbc_mode(void);
flea_err_t THR_flea_test_ctr_mode_1(void);
flea_err_t THR_flea_test_ctr_mode_parts(void);
flea_err_t THR_flea_test_ctr_mode_prng(void);

flea_err_t THR_flea_test_rsa_loop( unsigned loop_cnt);

flea_err_t THR_flea_test_rsa_crt_mass_sig( flea_u32_t nb_iters);

flea_err_t THR_flea_test_dbg_canaries(void);

flea_err_t THR_flea_test_crc16(void);


int flea_unit_tests(flea_u32_t rnd);


#ifdef __cplusplus
}
#endif
#endif /* h-guard */
