//***************************************************************************************
// gf2exp4.h
// GF(2^4) fast operations
//
// Copyright © 2021 Dmitry Schelkunov. All rights reserved.
// Contacts: <d.schelkunov@gmail.com>, <schelkunov@re-crypt.com>
//
// This file is a part of wb_poc
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

#ifndef GF2EXP4_H
#define GF2EXP4_H

#include <stdint.h>

namespace NGF2exp4
{
	uint8_t get_poly_by_index(int i);
	uint8_t gmul_tab(uint8_t a, uint8_t b, uint8_t p);
	uint8_t inv_tab(uint8_t b, uint8_t p);
	uint8_t gdiv_tab(uint8_t a, uint8_t b, uint8_t p);
}

#endif // GF2EXP4_H