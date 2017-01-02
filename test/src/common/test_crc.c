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
#include "flea/hash.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/crc.h"
#include "flea/algo_config.h"
#include <string.h>

flea_err_t THR_flea_test_crc16 ()
{
  FLEA_THR_BEG_FUNC();
  flea_u16_t crc_init_value__u16 = 0; 
  flea_u16_t exp_res__u16 = 0xC965;   // APPROVED BY 2 ONLINE CALCULATORS
  flea_u16_t crc_res__u16;
  flea_u8_t test_string__au8[] = { 0xAB, 0xCD };
  crc_res__u16 = flea_crc16_ccit_compute(crc_init_value__u16, test_string__au8, sizeof(test_string__au8));

  if(crc_res__u16 != exp_res__u16)
  {
    FLEA_THROW("wrong CRC16 result", FLEA_ERR_FAILED_TEST);
  }
  crc_res__u16 = flea_crc16_ccit_compute(crc_init_value__u16, &test_string__au8[0], 1);
  crc_res__u16 = flea_crc16_ccit_compute(crc_res__u16, &test_string__au8[1], 1);
  if(crc_res__u16 != exp_res__u16)
  {
    FLEA_THROW("wrong CRC16 result", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}
