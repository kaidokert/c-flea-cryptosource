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


#ifndef _flea_array_util_H_
#define _flea_array_util_H_

#define FLEA_SET_ARR(__dst, __val, __count) \
  memset(__dst, __val, sizeof((__dst)[0]) * (__count))

#define FLEA_CP_ARR(__dst, __src, __count) \
  memcpy(__dst, __src, sizeof((__dst)[0]) * (__count))

#define FLEA_NB_ARRAY_ENTRIES_WLEN(__arr, __size_in_bytes) ((__size_in_bytes) / sizeof((__arr)[0]))

#define FLEA_NB_ARRAY_ENTRIES(__arr) FLEA_NB_ARRAY_ENTRIES_WLEN((__arr), sizeof(__arr))

#endif /* h-guard */
