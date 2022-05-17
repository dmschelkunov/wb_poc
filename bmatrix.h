//***************************************************************************************
// bmatrix.h
// Operations with binary matrices
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

#include <stdint.h>

#ifndef BMATRIX_H
#define BMATRIX_H

namespace NBMatrix
{

//
// Bit value (for implementation of indexing operators)
//
class CBitVal
{
public:
	static uint8_t get_bitval_by_index(const uint64_t* p, uint32_t i)
	{
		return (uint8_t)((p[i / (sizeof(uint64_t) << 3)] >> (i % (sizeof(uint64_t) << 3))) & 1);
	}

	static void set_bitval_by_index(uint64_t* p, uint32_t i, bool val)
	{
		uint64_t t = ((uint64_t)1) << (i % (sizeof(uint64_t) << 3));

		if (val)
			p[i / (sizeof(uint64_t) << 3)] |= t;
		else
			p[i / (sizeof(uint64_t) << 3)] &= ~t;
	}

public:	
	CBitVal(uint64_t* p, int i) : m_p(p), m_i(i){};
	CBitVal(const CBitVal& bv) : m_p(bv.m_p), m_i(bv.m_i){};
	~CBitVal(){};

private:
	CBitVal operator=(const CBitVal& bv){
		m_p = bv.m_p;
		m_i = bv.m_i;
		return *this;
	};

public:
	bool operator=(bool b)
	{
		set_bitval_by_index(m_p, m_i, b);
		return *this;
	}

public:
	operator bool() const{
		return get_bitval_by_index(m_p, m_i) ? true : false;
	}

	operator unsigned char() const{
		return get_bitval_by_index(m_p, m_i);
	}

	operator char() const{
		return (char)get_bitval_by_index(m_p, m_i);
	}

	operator unsigned long() const{
		return get_bitval_by_index(m_p, m_i);
	}

	operator long() const{
		return (long)get_bitval_by_index(m_p, m_i);
	}

	operator unsigned short() const{
		return get_bitval_by_index(m_p, m_i);
	}

	operator short() const{
		return (short)get_bitval_by_index(m_p, m_i);
	}

	operator unsigned long long() const{
		return get_bitval_by_index(m_p, m_i);
	}

	operator long long() const{
		return (long long)get_bitval_by_index(m_p, m_i);
	}

private:
	uint64_t	*m_p;		// pointer to associated array
	int			m_i;		// index of bit value
};

//
// N-bit binary array
//
template<int N>
class TBArray
{
public:
	enum{ array_size = N / (sizeof(uint64_t) << 3) + 1 };
	typedef uint64_t array_type[N / (sizeof(uint64_t) << 3) + 1];
	enum{ shrink_mask = ~(((uint64_t)-1) << (N % (sizeof(uint64_t) << 3))) };
	enum{ bit_size = N };

public:
	TBArray(){
		for (int i(0); i < array_size; ++i)
		{
			m_array[i] = 0;
		}
	};

	TBArray(const TBArray<N>& a){
		for (int i(0); i < array_size; ++i)
		{
			m_array[i] = a.m_array[i];
		}
	};
	
	TBArray(const array_type& a){
		for (int i(0); i < array_size; ++i)
		{
			m_array[i] = a[i];
		}
	}
	~TBArray(){}

public:
	TBArray<N>& operator=(const TBArray<N>& a){
		for (int i(0); i < array_size; ++i)
		{
			m_array[i] = a.m_array[i];
		}

		return *this;
	}

public:
	bool operator==(const TBArray<N>& a) const{
		for (int i(0); i < array_size; ++i)
		{
			if (m_array[i] != a.m_array[i])
				return false;
		}

		return true;
	}

	bool operator!=(const TBArray<N>& a) const{
		return !(*this == a);
	}

	TBArray<N> operator~() const{
		TBArray<N> cpy(*this);
		for (int i(0); i < array_size; ++i)
		{
			cpy.get_internal_array[i] = ~cpy.get_internal_array[i];
		}

		return cpy;
	}

	TBArray<N> operator^(const TBArray& a) const{
		TBArray<N> cpy(*this);
		for (int i(0); i < array_size; ++i)
			cpy.get_internal_array[i] ^= cpy.get_internal_array[i];
				
		cpy.get_internal_array[array_size - 1] &= shrink_mask;

		return cpy;
	}

	TBArray<N> operator+(const TBArray& a) const{
		return (*this ^ a);
	}

	void operator^=(const TBArray& a) {
		for (int i(0); i < array_size; ++i)
			m_array[i] ^= a.m_array[i];
			
		m_array[array_size - 1] &= shrink_mask;
	}

	void operator+=(const TBArray& a){
		*this ^= a;
	}

	TBArray<N> operator<<(int l) const{
		TBArray<N> cpy(*this);

		cpy.lshift(l);

		return cpy;
	}

	void operator<<=(int l) {
		lshift(l);
	}

	TBArray<N> operator>>(int r) const{
		TBArray<N> cpy(*this);

		cpy.rshift(r);

		return cpy;
	}

	void operator>>=(int r) {
		rshift(r);
	}

public:
	void lshift_to_one(){
		bool b(false);
		uint64_t mask(0);
		for (int i = 0; i < array_size; ++i)
		{
			mask = m_array[i] >> ((sizeof(uint64_t) << 3) - 1);
			m_array[i] <<= 1;
			m_array[i] ^= b ? 1 : 0;
			b = mask != 0;
		}

		m_array[array_size - 1] &= shrink_mask;
	}

	void rshift_to_one(){
		for (int i = 0; i < array_size; ++i)
		{
			m_array[i] >>= 1;
			if (i != array_size - 1)
				m_array[i] ^= m_array[i + 1] << ((sizeof(uint64_t) << 3) - 1);
		}
	}

	void lshift(int l)
	{
		if (l == 0)
			return;

		if (l >= N)
		{
			for (int i = 0; i < N; ++i)
				m_array[i] = 0;
			return;
		}

		int qword_shift = l / (sizeof(uint64_t) << 3);
		int rem_shift = l % (sizeof(uint64_t) << 3);

		if (qword_shift)
		{
			for (int i = array_size - 1; i > 0; --i)
			{
				if (i < qword_shift)
					m_array[i] = 0;
				else
					m_array[i] = m_array[i - qword_shift];
			}

			m_array[0] = 0;
		}

		uint64_t prev_mask(0);
		for (int i = 0; i < array_size; ++i)
		{
			uint64_t t = m_array[i] >> ((sizeof(uint64_t) << 3) - rem_shift);
			m_array[i] <<= rem_shift;
			m_array[i] |= prev_mask;
			prev_mask = t;
		}

		uint64_t low_mask = (uint64_t)-1 >> ((sizeof(uint64_t) << 3) - N % (sizeof(uint64_t) << 3));
		m_array[array_size - 1] &= low_mask;
	}

	void rshift(int r)
	{
		if (r == 0)
			return;

		TBArray<N> cpy(*this);		

		if (r >= N)
		{
			for (int i = 0; i < N; ++i)
				m_array[i] = 0;
			return;
		}

		int qword_shift = r / (sizeof(uint64_t) << 3);
		int rem_shift = r % (sizeof(uint64_t) << 3);

		if (qword_shift)
		{
			for (int i = 0; i < array_size; ++i)
			{
				if ((i + qword_shift) >= array_size)
					m_array[i] = 0;
				else
					m_array[i] = m_array[i + qword_shift];
			}
		}

		for (int i = 0; i < array_size; ++i)
		{
			m_array[i] >>= rem_shift;
			if (i != (array_size - 1))
				m_array[i] |= m_array[i + 1] << ((sizeof(uint64_t) << 3) - rem_shift);
		}

		// sorry for that...
		for (int i = 0; i < r; ++i)
			cpy.rshift_to_one();
}


public:
	array_type& get_internal_array(){
		return m_array;
	}

	const array_type& get_internal_array() const{
		return m_array;
	}

	void clear(){
		for (int i = 0; i < array_size; ++i)
			m_array[i] = 0;
	}

public:	
	uint8_t operator[](int i) const{
		return CBitVal::get_bitval_by_index(m_array, i);
	}
	CBitVal operator[](int i){
		return CBitVal(m_array, i);
	}

private:
	array_type	m_array;
};

//
// Binary matrix with N rows and M columns
//
template<int N, int M>
class TBMatrix
{
public:
	enum{ raws = N, cols = M };

public:
	typedef TBArray<M> matrix_type[N];

public:
	TBMatrix(){}
	TBMatrix(const TBMatrix<N, M>& r){
		for (int i = 0; i < N; ++i)
		{
			m_M[i] = r.m_M[i];
		}
	}

public:
	TBMatrix<N, M>& operator=(const TBMatrix<N, M>& r){
		for (int i = 0; i < N; ++i)
		{
			m_M[i] = r.m_M[i];
		}

		return *this;
	}

public:
	bool operator==(const TBMatrix<N, M>& r) const{
		for (int i = 0; i < N; ++i)
		{
			if (m_M[i] != r.m_M[i])
				return false;
		}

		return true;
	}

	bool operator!=(const TBMatrix<N, M>& r) const{
		return !(*this == r);
	}

public:
	const TBArray<M>& operator[](int i) const{
		return m_M[i];
	}

	TBArray<M>& operator[](int i){
		return m_M[i];
	}

public:
	// Will optimize it later, but it's enough for now
	template<int K>
	TBMatrix<N, K> operator*(const TBMatrix<M, K>& mr) const{
		TBMatrix<N, K> res;
		for (int i = 0; i < N; ++i)
		{
			for (int j = 0; j < M; ++j)
			{
				uint8_t t(0);
				// multiply i-th row of the left matrix with j-th column of the right one
				for (int k = 0; k < M; ++k)
				{
					t ^= m_M[i][k] & mr[k][j];
				}

				res[i][j] = t ? true : false;
			}
		}

		return res;
	}

	template<int K>
	void operator*=(const TBMatrix<M, K>& mr){
		*this = *this * mr;
	}

	// multiply with transposed vector
	TBArray<N> operator*(const TBArray<M>& r) const{
		TBArray<N> res;

		for (int i = 0; i < N; ++i)
		{
			uint8_t t(0);
			for (int j = 0; j < M; ++j)
			{
				t ^= m_M[i][j] & r[j];
			}

			res[i] = t ? true : false;
		}

		return res;
	}

public:
	void clear()
	{
		for (int i = 0; i < N; ++i)
			m_M[i].clear();
	}

private:
	matrix_type		m_M;
};

template<int N, int M>
void switch_rows(TBMatrix<N, M>& m, int i, int j)
{
	if (i == j)
		return;
	if (i >= N || j >= N)
		return;

	TBArray<M> t(m[i]);
	m[i] = m[j];
	m[j] = t;
}

template<int N, int M>
bool get_nzero_row(const TBMatrix<N, M>& m, int start_rindex, int start_cindex, int& rindex, int& cindex)
{
	if (start_rindex > start_cindex || start_rindex >= N || start_cindex >= M)
	{
		rindex = cindex = -1;
		return false;
	}

	for (int i = start_rindex; i < N; ++i)
	{
		if (m[i][start_cindex])
		{
			rindex = i;
			cindex = start_cindex;
			return true;
		}
	}
	
	return get_nzero_row(m, start_rindex, start_cindex + 1, rindex, cindex);
}

template<int N, int M>
void cadd_row_to_others(TBMatrix<N, M>& m, int r, int c)
{
	for (int i = 0; i < N; ++i)
	{
		if (i == r)
			continue;
		if (m[i][c])
		{
			m[i] ^= m[r];
		}
	}
}

template<int N, int M>
int rank(const TBMatrix<N, M>& m, TBMatrix<N, M>& rm)
{
	rm = m;
	int r(0), c(0), t0, t1;

	for (int i = 0; i < N; ++i)
	{
		if (get_nzero_row(rm, r, c, t0, t1))
		{
			c = t1;

			switch_rows(rm, r, t0);
			cadd_row_to_others(rm, r++, c++);
		}
		else
			return r;
	}

	return N;
}

template<int N, int M>
bool determinant(const TBMatrix<N, M>& m, TBMatrix<N, M>& rm)
{
	return (rank(m, rm) == N);
}

template <int N>
TBMatrix<N, N> unit_matrix()
{
	TBMatrix<N, N> m;
	for (int i = 0; i < N; ++i)
		m[i][i] = true;

	return m;
}

template <int N>
TBMatrix<N, 2 * N> append_unit_matrix(const TBMatrix<N, N>& m)
{
	TBMatrix<N, 2 * N> mx;
	for (int i = 0; i < N; ++i)
	{
		for (int j = 0; j < TBArray<N>::array_size; ++j)
		{
			mx[i].get_internal_array()[j] = m[i].get_internal_array()[j];
		}

		mx[i][i + N] = true;
	}

	return mx;
}

template <int N>
bool inverse(const TBMatrix<N, N>& m, TBMatrix<N, N>& inv)
{
	TBMatrix<N, 2 * N> adj(append_unit_matrix(m));

	int r(0), c(0), tr, tc;

	for (int i = 0; i < N; ++i)
	{
		if (!get_nzero_row(adj, r, c, tr, tc))
			return false;

		c = tc;

		switch_rows(adj, r, tr);
		cadd_row_to_others(adj, r++, c++);
	}

	for (int i = 0; i < N; ++i)
	{
		adj[i] >>= N;
		for (int j = 0; j < TBArray<N>::array_size; ++j)
			inv[i].get_internal_array()[j] = adj[i].get_internal_array()[j];
	}

	return true;
}

template<int M, int N, int U, int V>
TBMatrix<U, V> submatrix(const TBMatrix<M, N> m, int start_row, int start_col)
{
	TBMatrix<U, V> sm;
	for (int i = 0; i < U; ++i)
	{
		for (int j = 0; j < V; ++j)
		{
			sm[i][j] = m[i + start_row][j + start_col] ? true : false;
		}
	}

	return sm;
}

}

#endif // BMATRIX_H