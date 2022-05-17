//***************************************************************************************
// cipher.cpp
// Generator of a random cipher
//
// Copyright © 2022 Dmitry Schelkunov. All rights reserved.
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

#include "cipher.h"

namespace NCipher
{

template <int N>
struct TAdd1
{
	enum
	{
		add1 = 1
	};
};

template <>
struct TAdd1<0>
{
	enum
	{
		add1 = 0
	};
};

template <int N>
struct TBufSize
{
	struct down
	{
		enum
		{
			qwords = N / 64,
			dwords = N / 32,
			words = N / 16,
			bytes = N / 8
		};
	};
	
	struct up
	{
		enum 
		{
			qwords = down::qwords + TAdd1<N % 64>::add1,
			dwords = down::dwords + TAdd1<N % 32>::add1,
			words = down::words + TAdd1<N % 16>::add1,
			bytes = down::bytes + TAdd1<N % 8>::add1
		};
	};
};


template<int N>
void get_random_array(NBMatrix::TBArray<N>& a)
{
	uint64_t buf[TBufSize<N>::up::qwords];
	memset(buf, 0, TBufSize<N>::up::qwords << 3);
	NPrng::get_rnd(buf, TBufSize<N>::down::bytes);

	for (int i = 0; i < TBufSize<N>::up::qwords; ++i)
		a.get_internal_array()[i] = buf[i];

}

template <int N>
void get_random_square_matrix(NBMatrix::TBMatrix<N, N>& m)
{
	for (int i = 0; i < N; ++i)
		get_random_array(m[i]);
}

template <int N>
void get_random_invertable_square_matrix(NBMatrix::TBMatrix<N, N>& m)
{
	for (;;)
	{
		get_random_square_matrix(m);
		NBMatrix::TBMatrix<N, N> rm;
		
		if (NBMatrix::determinant(m, rm))
			break;
	}
}

void unit_sbox(uint8_t* sbx, uint32_t size)
{
	for (uint32_t i = 0; i < size; ++i)
		sbx[i] = (uint8_t)i;
}

void combine_tboxes(CEncryption::tbox& res, const CEncryption::tbox& t1, const CEncryption::tbox& t2)
{
	for (int i = 0; i < CEncryption::tbox_size; ++i)
		res[i] = t1[i] ^ t2[i];
}

CEncryption::CEncryption() : m_init(false)
{
}

CEncryption::~CEncryption()
{
}

CEncryption::CEncryption(const CEncryption &e) : m_bmtrx1(e.m_bmtrx1), m_bmtrx2(e.m_bmtrx2), m_init(e.m_init)
{
	memcpy_s(m_substs, sizeof(subst_arrays), e.m_substs, sizeof(subst_arrays));
	memcpy_s(m_tbxs, sizeof(tbox_arrays), e.m_tbxs, sizeof(tbox_arrays));
	memcpy_s(m_comb_tbxs, sizeof(comb_tbox_arrays), e.m_comb_tbxs, sizeof(comb_tbox_arrays));
}

const CEncryption& CEncryption::operator=(const CEncryption& e)
{
	m_init = e.m_init;
	m_bmtrx1 = e.m_bmtrx1;
	m_bmtrx2 = e.m_bmtrx2;

	memcpy_s(m_substs, sizeof(subst_arrays), e.m_substs, sizeof(subst_arrays));
	memcpy_s(m_tbxs, sizeof(tbox_arrays), e.m_tbxs, sizeof(tbox_arrays));
	memcpy_s(m_comb_tbxs, sizeof(comb_tbox_arrays), e.m_comb_tbxs, sizeof(comb_tbox_arrays));

	return *this;
}

bool CEncryption::is_init() const
{
	return m_init;
}

const NBMatrix::TBMatrix<CEncryption::bit_size1, CEncryption::bit_size1>& CEncryption::get_bmtrx1() const
{
	return m_bmtrx1;
}

const NBMatrix::TBMatrix<CEncryption::bit_size2, CEncryption::bit_size2>& CEncryption::get_bmtrx2() const
{
	return m_bmtrx2;
}

const CEncryption::subst_arrays& CEncryption::get_substs() const
{
	return m_substs;
}

const CEncryption::tbox_arrays&	CEncryption::get_tbxs() const
{
	return m_tbxs;
}
const CEncryption::comb_tbox_arrays& CEncryption::get_comb_tbxs() const
{
	return m_comb_tbxs;
}

void CEncryption::gen_sbox(uint8_t* sa, uint32_t sa_size)
{
	mpf_t x, p, left, right, s1, delta, imm;
	mpf_init2(x, 256);
	mpf_set(x, NPrng::seed);
	 
	mpf_init_set_d(imm, sa_size);
	mpf_init_set_d(p, 0.15);
	mpf_init_set_d(left, 0.1);
	mpf_init_set_d(right, 0.9);

	mpf_init2(s1, 256);
	mpf_init2(delta, 256);

	mpf_sub(s1, right, left);
	mpf_div(delta, s1, imm);

	uint32_t cnt(0);

	bool *is_init = new bool[sa_size];
	memset(is_init, 0, sa_size * sizeof(bool));

	for (; cnt < sa_size;)
	{
		NPrng::iterate_PLCM(x, x, p);

		mpf_t mf_index, s2;
		mpf_init2(mf_index, 256);
		mpf_init2(s2, 256);

		mpf_sub(s2, x, left);
		mpf_div(mf_index, s2, delta);

		uint8_t index = (uint8_t)mpf_get_d(mf_index);

		if (index < 0 || index > sa_size)
			continue;
		if (is_init[index])
			continue;

		is_init[index] = true;
		sa[cnt++] = index;
	}

	mpf_set(NPrng::seed, x);

	delete[] is_init;
}

void CEncryption::gen_sboxes()
{
	for (int i = 0; i < sbsts_num; ++i)
		gen_sbox(m_substs[i], sbst_size);
}

void CEncryption::gen_mtrx1()
{
	get_random_invertable_square_matrix(m_bmtrx1);
}

void CEncryption::gen_mtrx2()
{
	get_random_invertable_square_matrix(m_bmtrx2);
}

void CEncryption::gen_tbox_elem(tbox& telem, uint8_t elem, int index)
{
	uint64_t s[1];
	s[0] = m_substs[index][elem]; // lazy trick :)

	for (int i = 0; i < tbox_clear_size << 1; ++i)
	{

		NBMatrix::TBMatrix<sbx_elem_size, sbx_elem_size> m = \
			NBMatrix::submatrix<bit_size1, bit_size1, sbx_elem_size, sbx_elem_size>(m_bmtrx1, i * sbx_elem_size, \
			index * sbx_elem_size);

		NBMatrix::TBArray<sbx_elem_size> b(s);
		
		NBMatrix::TBArray<sbx_elem_size> c = m * b;

		uint8_t t = (uint8_t)c.get_internal_array()[0];
		if (i % 2)
			t <<= sbx_elem_size;
		else
			telem[i >> 1] = 0;

		telem[i >> 1] |= t;
	}
}

void CEncryption::gen_tbox(tbox_array& t, int index)
{
	for (int i = 0; i < sbst_size; ++i)
		gen_tbox_elem(t[i], i, index);
}

void CEncryption::gen_tboxes()
{
	for (int i = 0; i < sbsts_num; ++i)
		gen_tbox(m_tbxs[i], i);
}

void CEncryption::comb_tboxes()
{
	uint8_t high_mixes[comb_sbst_size];
	gen_sbox(high_mixes, comb_sbst_size);
	for (int i = 0; i < sbsts_num; i += 2)
	{
		tbox_array &tba1(m_tbxs[i]);
		tbox_array &tba2(m_tbxs[i + 1]);

		uint8_t mixes[comb_sbst_size];
		gen_sbox(mixes, comb_sbst_size);

		for (int v = 0; v < sbst_size; ++v)
		{
			for (int u = 0; u < sbst_size; ++u)
			{
				combine_tboxes(m_comb_tbxs[i / 2][u + (v << sbx_elem_size)], tba1[u], tba2[v]);
				m_comb_tbxs[i / 2][u + (v << sbx_elem_size)][tbox_size - 2] = mixes[u + (v << sbx_elem_size)];	// add low 8 mix bits
				m_comb_tbxs[i / 2][u + (v << sbx_elem_size)][tbox_size - 1] = high_mixes[i / 2];				// add high 8 mix bits

				// Mix by multiplying with second matrix
				
				NBMatrix::TBArray<bit_size2> b;
				for (int j = 0; j < bit_size2 >> 3; ++j)
					((uint8_t*)b.get_internal_array())[j] = m_comb_tbxs[i / 2][u + (v << sbx_elem_size)][j];

				b = m_bmtrx2 * b;

				for (int j = 0; j < bit_size2 >> 3; ++j)
					m_comb_tbxs[i / 2][u + (v << sbx_elem_size)][j] = ((uint8_t*)b.get_internal_array())[j];
			}
		}
	}
}

void CEncryption::gen_key()
{
	gen_sboxes();
	gen_mtrx1();
	gen_mtrx2();
	gen_tboxes();
	comb_tboxes();
	m_init = true;
}


CDecryption::CDecryption(const CEncryption& e) : m_init(false), m_e(e)
{
}

CDecryption::~CDecryption()
{
}

CDecryption::CDecryption(const CDecryption& d) : m_init(d.m_init), m_e(d.m_e), m_inv_bmtrx1(d.m_inv_bmtrx1), m_inv_bmtrx2(d.m_inv_bmtrx2)
{
	memcpy_s(m_inv_comb_tbxs1, sizeof(clear_comb_tbox_arrays), d.m_inv_comb_tbxs1, sizeof(clear_comb_tbox_arrays));
	memcpy_s(m_inv_comb_tbxs2, sizeof(mixed_comb_tbox_arrays), d.m_inv_comb_tbxs2, sizeof(mixed_comb_tbox_arrays));
	memcpy_s(m_inv_comb_substs, sizeof(subst_arrays), d.m_inv_comb_substs, sizeof(subst_arrays));
	memcpy_s(m_final_tbxs, sizeof(clear_comb_tbox_arrays), d.m_final_tbxs, sizeof(clear_comb_tbox_arrays));
}

const CDecryption& CDecryption::operator=(const CDecryption& d)
{
	m_init = d.m_init;
	m_e = d.m_e;

	m_inv_bmtrx1 = d.m_inv_bmtrx1;
	m_inv_bmtrx2 = d.m_inv_bmtrx2;

	memcpy_s(m_inv_comb_tbxs1, sizeof(clear_comb_tbox_arrays), d.m_inv_comb_tbxs1, sizeof(clear_comb_tbox_arrays));
	memcpy_s(m_inv_comb_tbxs2, sizeof(mixed_comb_tbox_arrays), d.m_inv_comb_tbxs2, sizeof(mixed_comb_tbox_arrays));
	memcpy_s(m_inv_comb_substs, sizeof(subst_arrays), d.m_inv_comb_substs, sizeof(subst_arrays));
	memcpy_s(m_final_tbxs, sizeof(clear_comb_tbox_arrays), d.m_final_tbxs, sizeof(clear_comb_tbox_arrays));

	return *this;
}

const CEncryption& CDecryption::get_encr() const
{
	return m_e;
}

CEncryption& CDecryption::get_encr()
{
	return m_e;
}

bool CDecryption::is_init() const
{
	return m_init;
}

const CDecryption::mixed_comb_tbox_arrays& CDecryption::get_inv_comb_tbxs2() const
{
	return m_inv_comb_tbxs2;
}
const CDecryption::clear_comb_tbox_arrays& CDecryption::get_inv_comb_tbxs1() const
{
	return m_inv_comb_tbxs1;
}
const CDecryption::clear_comb_tbox_arrays& CDecryption::get_final_tbxs() const
{
	return m_final_tbxs;
}

bool CDecryption::init()
{
	gen_inv_matricies();
	gen_inv_sbox();
	gen_inv_tbxs2(); 
	gen_inv_tbxs1(); 
	gen_final_tboxes();
	
	return (m_init = true);
}

void CDecryption::gen_inv_matricies()
{
	NBMatrix::inverse(m_e.get_bmtrx1(), m_inv_bmtrx1);
	NBMatrix::inverse(m_e.get_bmtrx2(), m_inv_bmtrx2);
}

void CDecryption::gen_inv_sbox()
{
	for (int i = 0; i < CEncryption::sbsts_num; i += 2)
	{
		uint8_t index, inv;
		for (uint8_t u = 0; u < CEncryption::sbst_size; ++u)
		{ 
			for (uint8_t v = 0; v < CEncryption::sbst_size; ++v)
			{
				index = u | (v << CEncryption::sbx_elem_size);
				inv = m_e.get_substs()[i][u] | (m_e.get_substs()[i + 1][v] << CEncryption::sbx_elem_size);
				m_inv_comb_substs[i / 2][inv] = index;
			}
		}
	}
}

void unit_sbox(CDecryption::comb_subst_array& a)
{
	unit_sbox((uint8_t*)&a, CEncryption::comb_sbst_size);
}

template <typename MTRX>
void CDecryption::gen_tbox_elem(uint8_t *ptelem, int telem_size, uint8_t elem, int index)
{
	comb_subst_array us;
	unit_sbox(us);

	uint64_t s[1];
	s[0] = us[elem]; // lazy trick :)

	const MTRX& ibm = get_mtrx<MTRX>();

	for (int i = 0; i < telem_size; ++i)
	{
		NBMatrix::TBMatrix<CEncryption::comb_elem_size, CEncryption::comb_elem_size> m = \
			NBMatrix::submatrix<MTRX::raws, MTRX::cols, CEncryption::comb_elem_size, CEncryption::comb_elem_size>(ibm, i * CEncryption::comb_elem_size,
			index * CEncryption::comb_elem_size);

		NBMatrix::TBArray<CEncryption::comb_elem_size> b(s);

		NBMatrix::TBArray<CEncryption::comb_elem_size> c = m * b;

		uint8_t t = (uint8_t)c.get_internal_array()[0];

		ptelem[i] = t;
	}
}

void CDecryption::gen_inv_tbxs2()
{
	for (int i = 0; i < CEncryption::tbox_size; ++i)
	{
		for (int j = 0; j < CEncryption::comb_sbst_size; ++j)
		{
			gen_tbox_elem<NBMatrix::TBMatrix<CEncryption::bit_size2, CEncryption::bit_size2> >(&m_inv_comb_tbxs2[i][j][0], CEncryption::tbox_size, j, i);
		}
	}
}

void CDecryption::gen_inv_tbxs1()
{
	for (int i = 0; i < CEncryption::tbox_clear_size; ++i)
	{
		for (int j = 0; j < CEncryption::comb_sbst_size; ++j)
		{
			gen_tbox_elem<NBMatrix::TBMatrix<CEncryption::bit_size1, CEncryption::bit_size1> >(&m_inv_comb_tbxs1[i][j][0], CEncryption::tbox_size, j, i);
		}
	}
}

void CDecryption::gen_final_tboxes()
{
	for (int i = 0; i < CEncryption::tbox_clear_size; ++i)
	{
		for (int j = 0; j < CEncryption::comb_sbst_size; ++j)
		{
			memset(m_final_tbxs[i][j], 0, CEncryption::tbox_clear_size);
			m_final_tbxs[i][j][i] = m_inv_comb_substs[i][j];
		}
	}
}

};