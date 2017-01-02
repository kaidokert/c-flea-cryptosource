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
#include "self_test.h"
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include "pc/test_util.h"

flea_err_t THR_flea_test_sha256_file_based()
{
  std::string leaf_name = "sha256_test.dat";
  std::string file_name = "misc/testdata/" + leaf_name; 

  
  std::ifstream input(file_name.c_str()); 


  bool end = false;
  try
  {
    while(!end)
    {
      std::vector<flea_u8_t> m = parse_line("m", 0, input);
      std::vector<flea_u8_t> d = parse_line("d", 0, input);

      std::string line;
      if(!getline(input, line))
      {
        std::cout << "file error" << std::endl;
        return FLEA_ERR_INT_ERR;
      }
      if(line.find(std::string("next")) == 0)
      {
        //std::cout << "next test: " << line << std::endl;
        // nothing to do
      }
      else if(line.find(std::string("end")) == 0)
      {
        end = true;
      }
      //std::cout << "testing hash with message size = " << m.size() << std::endl;
      if(0 != THR_flea_test_hash_function_inner(
              &m[0], m.size(),
              &d[0], d.size(),
              flea_sha256 
            ))
          {
            return FLEA_ERR_FAILED_TEST;
          }
            

    } // end while loop
  }
  catch(std::exception & e)
  {
    std::cout << "error during the parsing of test data" << e.what() << std::endl;
    throw(e);
  }
  return FLEA_ERR_FINE;
}
