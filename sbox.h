//***************************************************************************************
// sbox.h
// A generator of chaotic S-box-es
//
// Copyright © 2009-2010, 2016-2017 Dmitry Schelkunov. All rights reserved.
// Contacts: <d.schelkunov@gmail.com>, <http://dschelkunov.blogspot.com/>
//
// This file is part of wb_poc.
//
// wb_poc is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// wb_poc is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with wb_poc. If not, see <http://www.gnu.org/licenses/>.
//***************************************************************************************

#include <stdint.h>
#include <vector>

#ifndef SBOX_H
#define SBOX_h

namespace NWhiteBox
{

void create_8bit_sboxes_chaotically(std::vector<uint8_t>&);
void create_4bit_sboxes_chaotically(std::vector<uint8_t>&);

}

#endif // SBOX_h