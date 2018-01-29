
#include "ecc.h"


bool is_null(const EPoint & point)
{
	return (point.x == 0 && point.y == 0);
}

bool is_null(const JPoint & jpoint)
{
	return (jpoint.x == 0 && jpoint.y == 0);
}

// Transform point p given as (x, y) to projective coordinates
JPoint to_projective(const EPoint & point)
{
	JPoint jpoint;
	jpoint.x = point.x;
	jpoint.y = point.y;

	if (is_null(point))
	{
		jpoint.z0 = jpoint.z1 = jpoint.z2 = 0;
		return jpoint;
	}

	jpoint.z0 = jpoint.z1 = jpoint.z2 = 1;
	return jpoint;
}

// Transform a point from projective coordinates to (x, y) mod n
EPoint from_projective(const JPoint & jpoint, const cpp_int & n)
{
	EPoint point;
	if (is_null(jpoint))
	{
		point.x = point.y = 0;
	}
	else
	{
		point.x = mod((jpoint.x * inv_mod(jpoint.z1, n)), n);
		point.y = mod((jpoint.y * inv_mod(jpoint.z2, n)), n);
	}

	return point;
}

// Compute the inverse point to p in affine coordinate system
template<typename T>
T neg(const T & point, const cpp_int & n)
{
	T pn;
	pn.x = point.x;
	pn.y = mod((n - point.y), n);

	return pn;
}


// '''Add points p and q over curve'''
EPoint add(const EPoint & p, const EPoint & q, const Curve & curve)
{
	if (is_null(p))
		return q;
	if (is_null(q))
		return p;

	EPoint r;
	cpp_int slope;
	cpp_int x;

	if (mod((p.x - q.x), curve.p) != 0)
	{
		slope = (p.y - q.y) * inv_mod(p.x - q.x, curve.p);
		slope = mod(slope, curve.p);
		x = slope * slope - p.x - q.x;
		x = mod(x, curve.p);				// intersection with curve
	}
	else
	{
		if (mod(p.y + q.y, curve.p) != 0)							// slope s calculated by derivation
		{
			slope = (3 * p.x * p.x - curve.a) * inv_mod(2 * p.y, curve.p);
			slope = mod(slope, curve.p);
			x = slope * slope - 2 * p.x;            			// intersection with curve
			x = mod(x, curve.p);
		}
	}
	r.x = x;
	r.y = p.y + slope * (x - p.x);
	r.y = curve.p - mod(r.y, curve.p);

	return r;
}

// explicit point doubling using redundant coordinates
// Double jp in projective (jacobian) coordinates
JPoint twice(const JPoint & pt, const Curve & curve)
{
	if (is_null(pt))
		return pt;

	JPoint ret;

	cpp_int y1p2 = (pt.y * pt.y) % curve.p;
	cpp_int a = (4 * pt.x * y1p2) % curve.p;
	cpp_int b = (3 * pt.x * pt.x - curve.a * pt.z2 * pt.z0) % curve.p;

	ret.x = (b * b - 2 * a) % curve.p;
	ret.y = (b * (a - ret.x) - 8 * y1p2 * y1p2) % curve.p;
	ret.z0 = (2 * pt.y * pt.z0) % curve.p;
	ret.z1 = (ret.z0 * ret.z0) % curve.p;
	ret.z2 = (ret.z1 * ret.z0) % curve.p;

	return ret;
}

// Add jp1 and jp2 in projective (jacobian) coordinates.
JPoint add(const JPoint & p, const JPoint & q, const Curve & curve)
{
	JPoint ret;

	if (is_null(p))
		return q;
	if (is_null(q))
		return p;

	cpp_int s1 = (p.y * q.z2) % curve.p;
	cpp_int s2 = (q.y * p.z2) % curve.p;

	cpp_int u1 = (p.x * q.z1) % curve.p;
	cpp_int u2 = (q.x * p.z1) % curve.p;

	if (((u1 - u2) % curve.p) != 0)
	{
		cpp_int h = (u2 - u1) % curve.p;
		cpp_int r = (s2 - s1) % curve.p;

		cpp_int hs = (h * h) % curve.p;
		cpp_int hc = (hs * h) % curve.p;

		ret.x = mod((r * r - hc - 2 * u1 * hs), curve.p);
		ret.y = mod((r * (u1 * hs - ret.x) - s1 * hc), curve.p);
		ret.z0 = mod((p.z0 * q.z0 * h), curve.p);

		ret.z1 = mod((ret.z0 * ret.z0), curve.p);
		ret.z2 = mod((ret.z1 * ret.z0), curve.p);
	}
	else
	{
		if (((s1 + s2) % curve.p) != 0)
			return twice(p, curve);
	}
	return ret;
}


// scalar multiplication k * p = p + p + ... + p (k times) in O(log(n))
// '''multiply point p by scalar k over curve (p, q, n)'''
JPoint mul(cpp_int k, JPoint p, const Curve & curve)
{
	JPoint r;
	r.x = r.y = 0;

	while (k > 0)
	{
		//if (k & 1)

		if ((k % 2) == 1)
		{
			r = add(r, p, curve);
		}
		k >>= 1;
		p = twice(p, curve);
	}

	return r;
}


// scalar multiplication k * p = p + p + ... + p (k times) in O(log(n))
// '''multiply point p by scalar k over curve (p, q, n)'''
EPoint mul(cpp_int k, EPoint p, const Curve & curve)
{
	return from_projective(mul(k, to_projective(p), curve), curve.p);
}