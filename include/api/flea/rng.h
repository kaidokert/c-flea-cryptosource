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



#ifndef __flea_rng_H_
#define __flea_rng_H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function for accessing the static RNG of the flea library.
 */


/**
 * Fill a memory area with random bytes using the global RNG.
 *
 * @param mem pointer to the memory area to be randomized
 * @param mem_len the length of the area to be randomized
 *
 */
void flea_rng__randomize(flea_u8_t* mem, flea_dtl_t mem_len);


/**
 * Reseed the global RNG state in RAM. The persistent NVM state is not affected.
 * Use this function to quickly update the RAM state without a time consuming
 * NVM-write operation.
 *
 * @param seed the seed data to be added
 * @param seed_len the length of seed
 *
 * @return flea error code
 */
flea_err_t  THR_flea_rng__reseed_volatile(const flea_u8_t* seed, flea_dtl_t seed_len);

/**
 * Reseed the global RNG state in RAM. The persistent NVM state is also set to a
 * new value. Use this function to let high entropy seed data take a lasting
 * effect on the RNG's entropy level.
 *
 * @param seed the seed data to be added
 * @param seed_len the length of seed
 *
 * @return flea error code
 */
flea_err_t THR_flea_rng__reseed_persistent(const flea_u8_t* seed, flea_dtl_t seed_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
