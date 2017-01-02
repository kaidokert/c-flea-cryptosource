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


#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include "pc/test_util.h"

std::vector<flea_u8_t> parse_line(const char* name, flea_u16_t result_size, std::ifstream & input)
{
  std::string line_start = std::string(name) + " = ";
  std::string line;
  if(!getline(input, line))
  {
    std::cout << "file error" << std::endl;
    throw std::exception();
  }
  if(line.find(line_start) != 0)
  {
    std::cout << "line error, name = " << std::string(name)  << std::endl;
    throw std::exception();
  }
  std::string value = line.substr(line_start.size());
  if(value.size() % 2)
  {
    std::cout << "size of string not multiple of 2" << std::endl;
  }
  std::vector<flea_u8_t> result;
  if(result_size)
  {
    result.resize(result_size);
  }
  else
  {
    result.resize(value.size()/2);
    result_size = result.size();
  }
  int offset = result_size - (value.size()+1)/2;
  if(offset < 0)
  {
    std::cout << "value size error: name = " << std::string(name) << ", result_size = " << result_size << ", value.size() = " << value.size() << ", offset = " << offset << std::endl;
    throw std::exception();
  }
  //std::memset(dest, 0, dest_size);
  for(unsigned i = 0; i < value.size(); i++)
  {

     //nibble = value[i] < (9 ?
     unsigned shift = i % 2 ? 0 : 4;
     unsigned char byte = 0;
     if(((unsigned)value[i]) >= 0x30 + 0 && ((unsigned)value[i]) <= 0x30 + 9)
     {
       byte = value[i]-0x30;
     }
     else if(((unsigned)value[i]) >= 0x41 + 0 && ((unsigned)value[i]) <= 0x41 + 6)
     {
       byte = value[i]-0x41+10;
     }
     else if(((unsigned)value[i]) >= 0x61 + 0 && ((unsigned)value[i]) <= 0x61 + 6)
     {
       byte = value[i]-0x61+10;
     }
     else
     {
       std::memset(&result[0], 0, result.size());
      std::cout << "value encoding error: '" << value[i] << "'"  << std::endl;
      throw std::exception();

     }
     result[i/2 + offset] |= byte << shift;
  }
  return result;
}
