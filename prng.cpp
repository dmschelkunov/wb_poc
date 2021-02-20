//***************************************************************************************
// prng.cpp
// Pseudorandom numbers generator (Windows specific)
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

#include "prng.h"
#include <iostream>

#ifdef WIN32
#pragma comment(lib, "crypt32.lib")
#include <Windows.h>
#include <Wincrypt.h>
#endif // WIN32

namespace NPrng
{

mpf_t seed;

void iterate_PLCM(mpf_t res, mpf_t x, mpf_t p)
{
	int cmp_z = mpf_cmp_d(x, 0);
	int cmp_p = mpf_cmp(x, p);
	int cmp_half = mpf_cmp_d(x, 0.5);
	int cmp_1 = mpf_cmp_d(x, 1);
	if (cmp_z >= 0 && cmp_p <= 0) // 0 <= x <= p
	{
		mpf_div(res, x, p);
	}
	else if (cmp_p && cmp_half <= 0) // p < x <= 0.5
	{
		mpf_t s1, s2, half_one;
		mpf_init2(s1, 256);
		mpf_init2(s2, 256);
		mpf_init2(half_one, 256);
		mpf_set_d(half_one, 0.5);

		mpf_sub(s1, x, p);
		mpf_sub(s2, half_one, p);
		mpf_div(res, s1, s2);
	}
	else if (cmp_half && cmp_1 <= 0) // 0.5 < x <= 1
	{
		mpf_t s1, one;
		mpf_init2(s1, 256);
		mpf_init2(one, 256);
		mpf_set_d(one, 1);
		mpf_sub(s1, one, x);
		
		iterate_PLCM(res, s1, p);
	}

}

#ifdef WIN32
class CWinSpecificPrngCtx
{
public:
	CWinSpecificPrngCtx()
	{
		if ( !::CryptAcquireContext(
			&m_hCryptProv,
			NULL,
			MS_ENH_RSA_AES_PROV,
			PROV_RSA_AES,
			CRYPT_NEWKEYSET))
		{
			DWORD err = ::GetLastError();
			if (err == NTE_EXISTS)
			{ 
				if (!::CryptAcquireContext(
					&m_hCryptProv,
					NULL,
					MS_ENH_RSA_AES_PROV,
					PROV_RSA_AES,
					CRYPT_DELETEKEYSET))
				{
					DWORD err = ::GetLastError();
					printf("ERROR: CryptAcquireContext!!!\n");
					exit(err);
				}
				if (m_hCryptProv)
					::CryptReleaseContext(m_hCryptProv, 0);

				if (!::CryptAcquireContext(
					&m_hCryptProv,
					NULL,
					MS_ENH_RSA_AES_PROV,
					PROV_RSA_AES,
					CRYPT_NEWKEYSET))
				{
					DWORD err = ::GetLastError();
					printf("ERROR: CryptAcquireContext!!!\n");
					exit(err);
				}
			}
			else
			{
				printf("ERROR: CryptAcquireContext!!!\n");
				exit(err);
			}
		}

		mpf_init2(seed, 256);

		uint8_t buf[32];

		if (!CryptGenRandom(
			m_hCryptProv,
			32,
			(PBYTE)buf))
		{
			printf("ERROR: CryptGenRandom!!!\n");
			DWORD err = ::GetLastError();
			exit(err);
		}

		char t[10];
		std::string s;

		for (uint32_t i = 0; i < 32; ++i)
		{
			sprintf_s(t, 10, "%u", buf[i]);
			s += t;
		}
		std::string::iterator it;
		uint32_t ex = 0;
		for (it = s.begin(); it != s.end() && ex < 4; ++it, ++ex){}

		s.insert(it, '.');
		s += "@-4";

		int e = mpf_set_str(seed, s.c_str(), 10);
		if (e)
		{
			printf("ERROR: mpf_set_str!!!\n");
			exit(e);
		}

	}

	void get(void* buf, uint32_t size, uint32_t len)
	{
		if (size < len)
			throw std::runtime_error("ERROR: Illegal size!!!\n");

		if (!CryptGenRandom(
			m_hCryptProv,
			len,
			(PBYTE)buf))
		{
			printf("ERROR: CryptGenRandom!!!\n");
			DWORD err = ::GetLastError();
			exit(err);
		}
	}

	void sha2(void* buf, uint32_t size, void* hsh, uint32_t hsh_size)
	{
		if (!buf || !hsh)
		{
			printf("ERROR: SHA2 null input!!!\n");
			exit(-1);
		}

		if (hsh_size != 32)
		{
			printf("ERROR: SHA2 size error!!!\n");
			exit(-1);
		}

		HCRYPTHASH hHash = 0;
		uint32_t obj_size = 32;
		if (!CryptCreateHash(m_hCryptProv, CALG_SHA_256, 0, 0, &hHash))
		{
			DWORD err = ::GetLastError();
			printf("ERROR: CryptCreateHash!!!\n");
			exit(err);
		}

		BYTE *data = new BYTE[obj_size];

		if (!CryptHashData(hHash, (PBYTE)buf, size, 0))
		{
			DWORD err = ::GetLastError();
			printf("ERROR: CryptHashData!!!\n");
			CryptDestroyHash(hHash);
			delete[] data;
			exit(err);
		}

		if (!CryptGetHashParam(hHash, HP_HASHVAL, data, (PDWORD)&obj_size, 0))
		{
			DWORD err = ::GetLastError();
			printf("ERROR: CryptHashData!!!\n");
			CryptDestroyHash(hHash);
			delete[] data;
			exit(err);
		}

		memcpy_s(hsh, hsh_size, data, obj_size);

		CryptDestroyHash(hHash);
		delete[] data;
	}

	~CWinSpecificPrngCtx()
	{
		if (m_hCryptProv)
			::CryptReleaseContext(m_hCryptProv, 0);
	}

private:
	HCRYPTPROV   m_hCryptProv;
};

CWinSpecificPrngCtx g_win_prng_ctx;

#endif // WIN32


void get_rnd(void* buf, uint32_t size)
{
#ifdef WIN32
	g_win_prng_ctx.get(buf, size, size);
#endif // WIN32
}

uint32_t get_rnd_32()
{
	
	uint32_t val;
#ifdef WIN32
	g_win_prng_ctx.get(&val, sizeof(val), sizeof(val));

#else
	//
	// TODO:
	//
#endif // WIN32
	return val;

}

uint8_t get_rnd_8()
{
	return (uint8_t)get_rnd_32();
}

uint8_t get_rnd_4()
{
	return (uint8_t)get_rnd_32() & 0xf;
}

void sha2(void* buf, uint32_t size, void* hsh, uint32_t hsh_size)
{
#ifdef WIN32
	g_win_prng_ctx.sha2(buf, size, hsh, hsh_size);
#else
	//
	// TODO:
	//
#endif // WIN32
}

}