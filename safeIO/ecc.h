#pragma once

#define CURVE_LEN 32
#include "romangol.h"
#include "cpp_int.h"

struct EPoint
{
	cpp_int x;
	cpp_int y;
};

struct JPoint
{
	cpp_int x;
	cpp_int y;
	cpp_int z0;
	cpp_int z1;
	cpp_int z2;
};

struct Curve
{
	size_t blockLen;
	cpp_int a;
	cpp_int b;
	cpp_int p;
	cpp_int n;
	EPoint G;
};

bool is_null(const EPoint & point);
bool is_null(const JPoint & point);
bool on_the_curve(const EPoint & point, const Curve & curve);

cpp_int		find_param_b(const EPoint & point, const cpp_int & a, const cpp_int & n);
JPoint		to_projective(const EPoint & point);
EPoint		from_projective(const JPoint & jpoint, const cpp_int & n);

EPoint		neg(const EPoint & point, const cpp_int & n);
EPoint		add(const EPoint & p, const EPoint & q, const Curve & curve);
EPoint 		mul(cpp_int k, EPoint p, const Curve & curve);

