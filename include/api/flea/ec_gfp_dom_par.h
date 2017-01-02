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


#ifndef _flea_ec_gfp_dom_par__H_
#define _flea_ec_gfp_dom_par__H_

#include "flea/types.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * The domain parameters predefined in flea.
 */
typedef enum
{
  flea_brainpoolP160r1,
  flea_brainpoolP192r1,
  flea_brainpoolP224r1,
  flea_brainpoolP256r1,
  flea_brainpoolP320r1,
  flea_brainpoolP384r1,
  flea_brainpoolP512r1,

  flea_secp112r1,
  flea_secp112r2,
  flea_secp128r1,
  flea_secp128r2,
  flea_secp160r1,
  flea_secp160r2,
  flea_secp192r1,
  flea_secp224r1,
  flea_secp256r1,
  flea_secp384r1,
  flea_secp521r1
} flea_ec_dom_par_id_t;

extern const flea_ec_dom_par_id_t flea_gl_ec_dom_par_max_id;
/**
 * id type of domain parameter elements.
 */
typedef enum { flea_dp__p = 0, flea_dp__a = 1, flea_dp__b = 2, flea_dp__Gx = 3, flea_dp__Gy = 4, flea_dp__n, flea_dp__h } flea_ec_dom_par_element_id_t;


/**
 *  Get a pointer to an element of the domain parameters in the flea internal
 *  format.
 *
 *  @param enc_dp domain parameters in flea internal format
 *  @param id id of the element to get the pointer to
 *
 *  @return a pointer to the specified element
 */
const flea_u8_t* flea_ec_dom_par__get_ptr_to_elem(const flea_u8_t* enc_dp, flea_ec_dom_par_element_id_t id);

/**
 * Get the real byte the length of the order n in the domain parameters (in
 * contrast to the encoded length, which might be longer than the real length
 * due to leading zero bytes)
 *
 *  @param enc_dp domain parameters in flea internal format
 *
 *  @return the length of the order
 */
flea_al_u8_t flea_ec_dom_par__get_real_order_byte_len(const flea_u8_t* enc_dp);

/**
 * Get the byte length of an element of the domain parameters specified by their id
 *
 * @param enc_dp domain parameters in flea internal format
 * @param id id of the element to the length of
 */
flea_al_u8_t flea_ec_dom_par__get_elem_len(const flea_u8_t* enc_dp, flea_ec_dom_par_element_id_t id);

/**
 * Get a pointer to the domain parameters in the flea internal format specified
 * by their id.
 *
 * @param dp_id id of the domain parameters

 * @return NULL if the domain parameters with the given id are not found,
 * otherwise a pointer to the domain parameters in the flea internal format
 */
const flea_u8_t* flea_ec_dom_par__get_predefined_dp_ptr(flea_ec_dom_par_id_t dp_id);

/**
 * Get the byte length of the domain parameters in the flea internal format specified
 * by their id.
 *
 * @param dp_id id of the domain parameters

 * @return 0 if the domain parameters with the given id are not found,
 * otherwise the byte length of the domain parameters in the flea internal format
 */
flea_al_u16_t flea_ec_dom_par__get_predefined_dp_len(flea_ec_dom_par_id_t dp_id);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
