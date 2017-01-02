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


#include "flea/types.h"

#ifndef _flea_lib__H_
#define _flea_lib__H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function must be called prior to any other function of the flea library
 * at the devices startup. If the return value of this function indicates an
 * error, then no cryptographic functions may be used.
 */
flea_err_t THR_flea_lib__init(void);

/**
 * Function that may be called at a point after which no more
 * functions of flea are used.
 */
void flea_lib__deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
