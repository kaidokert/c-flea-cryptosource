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



#ifndef _flea_ae_int__H_
#define _flea_ae_int__H_

typedef struct
{
  flea_u8_t pending__u8;
  flea_ctr_mode_ctx_t ctr_ctx__t;
  flea_mac_ctx_t cmac_ctx__t;
#ifdef FLEA_USE_HEAP_BUF
  flea_u8_t* nonce__bu8;
  flea_u8_t* header_omac__bu8;
  flea_u8_t* buffer__bu8;
#else
  flea_u8_t nonce__bu8 [FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t header_omac__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
  flea_u8_t buffer__bu8[FLEA_BLOCK_CIPHER_MAX_BLOCK_LENGTH];
#endif

} flea_ae_eax_specific_t;

/* fwd declaration */
struct flea_ae_config_entry_t;
typedef struct flea_ae_config_entry_struct flea_ae_config_entry_t;

#endif /* h-guard */
