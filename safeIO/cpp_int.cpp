#include "cpp_int.h"

cpp_int::cpp_int()
{
	init();
}

cpp_int::cpp_int(char *number)
{
	init();
	if (number[0] == '0' && (number[1] == 'x' || number[1] == 'X'))
	{
		BN_hex2bn(&this->num, &number[2]);
	}
	else
	{
		BN_hex2bn(&this->num, number);
	}

}

cpp_int::cpp_int(BIGNUM *number)
{
	init();
	BN_copy(this->num, number);
}

cpp_int::cpp_int(int number)
{
	init();
	BN_bin2bn((unsigned char*)&number, 4, this->num);
}

cpp_int::cpp_int(const cpp_int& b)
{
	init();
	BN_copy(this->num, b.num);
}

cpp_int cpp_int::FromUint8(uint8_t *bin, size_t len)
{
	BIGNUM* num = BN_new();
	BN_bin2bn((unsigned char*)bin, len, num);
	cpp_int res = cpp_int(num);
	BN_free(num);
	return res;
}

cpp_int cpp_int::FromDec(char * number)
{
	BIGNUM* num = BN_new();
	BN_dec2bn(&num, number);
	cpp_int res = cpp_int(num);
	BN_free(num);
	return res;

}

void ToUint8(cpp_int number, uint8_t *des)
{
	BN_bn2bin(number.getBignum(), des);
}

BIGNUM * cpp_int::getBignum()
{
	return this->num;
}

cpp_int::~cpp_int()
{
	BN_free(this->num);
	this->num = NULL;

	BN_CTX_free(bn_ctx);
	this->bn_ctx = NULL;
}

cpp_int  cpp_int::operator+(const cpp_int &b) const
{
	BIGNUM* result = BN_new();
	BN_add(result, this->num, b.num);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

cpp_int  cpp_int::operator+(const int& b)const
{
	return (*this) + cpp_int(b);
}

cpp_int  cpp_int::operator-(const cpp_int &b) const
{
	BIGNUM* result = BN_new();
	BN_sub(result, this->num, b.num);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

cpp_int  cpp_int::operator-(const int& b) const
{
	return (*this) - cpp_int(b);
}

cpp_int  cpp_int::operator*(const cpp_int &b) const
{
	BIGNUM* result = BN_new();
	BN_mul(result, this->num, b.num, this->bn_ctx);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

cpp_int  cpp_int::operator*(const int& b) const
{
	return (*this)*(cpp_int(b));
}

cpp_int  cpp_int::operator/(const cpp_int &b) const
{

	BIGNUM* result = BN_new();
	BN_div(result, NULL, this->num, b.num, this->bn_ctx);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

cpp_int  cpp_int::operator/(const int& b) const
{
	return (*this) / (cpp_int(b));
}

cpp_int  cpp_int::operator%(const cpp_int &b) const
{

	BIGNUM* result = BN_new();
	BN_mod(result, this->num, b.num, this->bn_ctx);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

//cpp_int cpp_int::operator^(const cpp_int &)
//{
//	return cpp_int();
//}

cpp_int cpp_int::operator >> (const int &b)
{
	BIGNUM* result = BN_new();
	BN_rshift(result, this->num, b);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

cpp_int cpp_int::operator<<(const int &b)
{

	BIGNUM* result = BN_new();
	BN_lshift(result, this->num, b);
	cpp_int res = cpp_int(result);
	BN_free(result);
	return res;
}

void cpp_int::operator>>=(const int& b)
{
	(*this) >> b;
}

cpp_int cpp_int::operator=(const cpp_int &b)
{
	BN_copy(this->num, b.num);
	return *this;
}

cpp_int cpp_int::operator=(const int& b)
{
	return cpp_int(b);
}

bool  cpp_int::operator==(const cpp_int &b) const
{
	return (BN_cmp(this->num, b.num) == 0);
}

bool  cpp_int::operator==(const int& b) const
{
	return (*this) == cpp_int(b);
}

bool cpp_int::operator!=(const cpp_int &b) const
{
	return !((*this) == b);
}

bool cpp_int::operator!=(const int& b) const
{
	return !((*this) == b);
}

bool cpp_int::operator>(const cpp_int &b)
{
	return (BN_cmp(this->num, b.num) == 1);
}

bool cpp_int::operator>(const int &b)
{
	return (*this) > cpp_int(b);
}

void cpp_int::init()
{
	this->num = BN_new();
	this->bn_ctx = BN_CTX_new();
}

cpp_int inv_mod(cpp_int a, cpp_int b)
{
	BIGNUM* tmp = BN_new();
	BN_mod_inverse(tmp, a.num, b.num, a.bn_ctx);
	cpp_int res = cpp_int(tmp);
	BN_free(tmp);
	return res;
}

cpp_int mod(cpp_int a, cpp_int b)
{
	return a%b;
}

cpp_int operator+(const int &b, const cpp_int &a)
{
	return a + b;
}

cpp_int operator-(const int &a, const cpp_int &b)
{
	return b - a;
}

cpp_int operator*(const int &a, const cpp_int &b)
{
	return b*a;
}

cpp_int operator/(const int &a, const cpp_int &b)
{
	return b / a;
}
