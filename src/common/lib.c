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


#include "internal/common/rng_int.h"
#include "flea/error_handling.h"

flea_err_t THR_flea_lib__init ()
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_rng__init());
  FLEA_THR_FIN_SEC_empty();
}

void flea_lib__deinit ()
{
  flea_rng__deinit();
}
