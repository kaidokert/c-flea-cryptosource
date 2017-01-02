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
#include "flea/types.h"
#include "flea/error.h"
flea_err_t THR_flea_test_flea_types ()
{
  FLEA_THR_BEG_FUNC();
  if(sizeof(flea_u8_t) != 1)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s8_t) != 1)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_u16_t) != 2)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s16_t) != 2)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_u32_t) != 4)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  if(sizeof(flea_s32_t) != 4)
  {
    FLEA_THROW("wrong size for type", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC();
}
