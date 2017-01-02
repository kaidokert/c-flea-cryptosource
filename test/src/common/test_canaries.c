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
#include <stdio.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"


#ifdef FLEA_USE_BUF_DBG_CANARIES

static flea_err_t THR_test_dbg_canaries_write_after_u32 ()
{
  // this function violates the canary values


  // also test correct handling of arrays with type different from u8
  FLEA_DECL_BUF(test_buf_u32, flea_u32_t, 2);
  FLEA_THR_BEG_FUNC();


  FLEA_ALLOC_BUF(test_buf_u32, 2);

  test_buf_u32[2] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf_u32);
    );

}
static flea_err_t THR_test_dbg_canaries_write_before_u32 ()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u32_t, 5);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(test_buf, 5);

  test_buf[-1] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf);

    );

}
static flea_err_t THR_test_dbg_canaries_write_after ()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u8_t, 5);

  // also test correct handling of arrays with type different from u8
  FLEA_DECL_BUF(test_buf_u32, flea_u32_t, 2);
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(test_buf, 5);

  FLEA_ALLOC_BUF(test_buf_u32, 2);

  test_buf[6] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf_u32);
    FLEA_FREE_BUF(test_buf);  // testing also FLEA_FREE_BUF() macro
    );

}
static flea_err_t THR_test_dbg_canaries_write_before ()
{
  // this function violates the canary values

  FLEA_DECL_BUF(test_buf, flea_u8_t, 5);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(test_buf, 5);

  test_buf[-1] += 1;


  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(test_buf);

    );

}

flea_err_t THR_flea_test_dbg_canaries ()
{

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_test_dbg_canaries_write_before());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_after());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_before_u32());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();
  FLEA_CCALL(THR_test_dbg_canaries_write_after_u32());
  if(!FLEA_IS_DBG_CANARY_ERROR_SIGNALLED())
  {
    FLEA_THROW("canary overwrite not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CLEAR_DBG_CANARY_ERROR();


  FLEA_THR_FIN_SEC_empty();

}
#else // #ifdef FLEA_USE_BUF_DBG_CANARIES

flea_err_t THR_flea_test_dbg_canaries ()
{
  return FLEA_ERR_FINE;
}
#endif // #else of #ifdef FLEA_USE_BUF_DBG_CANARIES
