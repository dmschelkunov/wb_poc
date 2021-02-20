//***************************************************************************************
// savekeys.h
// Save/Load keys
//
// Copyright © 2021 Dmitry Schelkunov. All rights reserved.
// Contacts: <d.schelkunov@gmail.com>, <schelkunov@re-crypt.com>
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

#include "cipher.h"

#ifndef SAVEKEYS_H
#define SAVEKEYS_H

namespace NSaveKeys
{

bool save_public_key(const char*, const NCipher::CEncryption&);
bool save_private_key(const char*, const NCipher::CDecryption&);
uint8_t* load_public_key(const char*);
uint8_t* load_priv_key(const char*);

}

#endif // SAVEKEYS_H
