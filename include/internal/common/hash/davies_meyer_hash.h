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


#ifndef _flea_davies_meyer_hash__H_
#define _flea_davies_meyer_hash__H_

#include "flea/error.h"
#include "flea/types.h"
#include "flea/hash.h"

void flea_hash_davies_meyer_aes128_init(flea_hash_ctx_t* ctx__pt);

flea_err_t THR_flea_hash_davies_meyer_aes128_compression(flea_hash_ctx_t* ctx__pt, const flea_u8_t* input);

#endif /* h-guard */
