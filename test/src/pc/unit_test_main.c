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


#include "self_test.h"
#include "stdio.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h> // Linux specific

int main (int argc, const char** argv)
{
  flea_u32_t rnd = 0;

  if(argc >= 2)
  {
    if( !strcmp(argv[1], "random"))
    {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      rnd = (tv.tv_sec * tv.tv_usec) ^ tv.tv_sec ^ tv.tv_usec;
      printf("rnd = %u\n", rnd);
    }
    else
    {
      printf("argument 1 must be 'random' or left out\n");
      exit(1);
    }
  }
  return flea_unit_tests(rnd);
}
