#pragma once
#include <windows.h>
#include <openssl/bn.h>

#include <stdint.h>

class cpp_int
{
public:
	cpp_int();
	cpp_int(char*);
	cpp_int(BIGNUM*);
	cpp_int(int);
	cpp_int(const cpp_int&);
	static cpp_int FromUint8(uint8_t*, size_t);
	static cpp_int FromDec(char* number);

	friend void ToUint8(cpp_int, uint8_t*);

	friend cpp_int inv_mod(cpp_int a, cpp_int b);
	friend cpp_int mod(cpp_int a, cpp_int b);

	BIGNUM* getBignum();


	~cpp_int();
	cpp_int  operator+(const cpp_int&)const;
	cpp_int  operator+(const int&)const;
	friend cpp_int operator + (const int&, const cpp_int&);

	cpp_int  operator-(const cpp_int&)const;
	cpp_int  operator-(const int&)const;
	friend cpp_int operator - (const int&, const cpp_int&);

	cpp_int  operator*(const cpp_int&)const;
	cpp_int  operator*(const int&)const;
	friend cpp_int operator * (const int&, const cpp_int&);


	cpp_int  operator/(const cpp_int&)const;
	cpp_int  operator/(const int&)const;
	friend cpp_int operator / (const int&, const cpp_int&);

	cpp_int  operator%(const cpp_int&)const;

	//cpp_int operator^(const cpp_int&);

	cpp_int operator >> (const int&);
	cpp_int operator << (const int&);

	void operator >>= (const int&);

	cpp_int operator = (const cpp_int&);
	cpp_int operator = (const int&);
	bool  operator == (const cpp_int&)const;
	bool  operator == (const int&)const;
	bool  operator != (const cpp_int&)const;
	bool  operator != (const int&)const;

	bool operator > (const cpp_int&);
	bool operator > (const int &);



private:
	void init();
	BIGNUM* num;
	BN_CTX* bn_ctx;
};

