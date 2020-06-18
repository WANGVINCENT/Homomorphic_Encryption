package security.generic;

/*

This is the Java implementation of the C++ NTL Library
Please refer to this site for NTL documentation:
http://www.shoup.net/ntl/doc/tour.html
http://www.shoup.net/ntl/doc/ZZ.txt

Credits to Andrew Quijano for code conversion 
and Samet Tonyali for helping on revising the code/debugging it.

Feel free to use this code as you like.
 */

import java.math.BigInteger;
import java.security.SecureRandom;

public class NTL implements CipherConstants
{
	private static SecureRandom rnd = new SecureRandom();

	// AKS Test
	// array used to store coefficients . 
	static long c[] = new long[100]; 

	// function to calculate the coefficients 
	// of (x - 1)^n - (x^n - 1) with the help 
	// of Pascal's triangle . 
	static void coef(long n) 
	{ 
		c[0] = 1; 
		for (int i = 0; i < n; c[0] = -c[0], i++) 
		{
			c[1 + i] = 1; 
			for (int j = i; j > 0; j--) 
			{
				c[j] = c[j - 1] - c[j]; 
			}
		} 
	} 

	// function to check whether 
	// the number is prime or not 
	static boolean isPrime(int n) 
	{ 
		// Calculating all the coefficients by 
		// the function coef and storing all 
		// the coefficients in c array . 
		coef(n); 

		// subtracting c[n] and adding c[0] by 1 
		// as ( x - 1 )^n - ( x^n - 1), here we 
		// are subtracting c[n] by 1 and adding 
		// 1 in expression. 
		c[0]++; 
		c[n]--; 

		// checking all the coefficients whether 
		// they are divisible by n or not. 
		// if n is not prime, then loop breaks 
		// and (i > 0). 
		int i = n; 
		while ((i--) > 0 && c[i] % n == 0); 

		// Return true if all coefficients are 
		// divisible by n. 
		return i < 0; 
	}

	public static BigInteger POSMOD(BigInteger x, BigInteger n)
	{
		BigInteger answer = x.mod(n).add(n).mod(n);
		return answer;
	}

	public static long POSMOD(long x, long n)
	{
		return ((x % n) + n) % n;
	}

	public static BigInteger POSMOD(long x, BigInteger n)
	{
		return POSMOD(BigInteger.valueOf(x), n);
	}

	// Ensure it is n-bit Large number and positive as well
	public static BigInteger generateXBitRandom (int bits)
	{
		BigInteger r = new BigInteger(bits, rnd);
		r = r.setBit(bits - 1);
		return r;
	}

	/*
	void RandomBnd(ZZ& x, const ZZ& n);
	ZZ RandomBnd(const ZZ& n);
	void RandomBnd(long& x, long n);
	long RandomBnd(long n);
	x = pseudo-random number in the range [0..n-1], or 0 if n <= 0
	 */

	public static BigInteger RandomBnd(long n)
	{
		return RandomBnd(BigInteger.valueOf(n));
	}

	public static BigInteger RandomBnd(BigInteger n)
	{
		if (n.signum() <= 0)
		{
			return BigInteger.ZERO;
		}
		BigInteger r;
		do
		{
			r = new BigInteger(n.bitLength(), rnd);
		}
		while (r.signum()== -1 || r.compareTo(n) >= 0);
		// 0 <= r <= n - 1
		// if r is negative or r >= n, keep generating random numbers
		return r;
	}

	// https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9
	public static BigInteger jacobi(BigInteger a, BigInteger n)
	{
		if (a.equals(BigInteger.ZERO))
		{
			return BigInteger.ZERO;
		}
		if (a.equals(BigInteger.ONE))
		{
			return BigInteger.ONE;
		}
		BigInteger e = BigInteger.ZERO;
		BigInteger a1 = a;
		while (a1.mod(TWO).equals(BigInteger.ZERO))
		{
			e = e.add(BigInteger.ONE);
			a1 = a1.divide(TWO);
		}

		// assert 2**e * a1 == a;
		BigInteger s = BigInteger.ZERO;
		BigInteger temp = n.mod(EIGHT);

		if (e.mod(TWO).equals(BigInteger.ZERO))
		{
			s = BigInteger.ONE;
		}
		// n % 8 in {1, 7}
		else if (temp.equals(BigInteger.ONE) || temp.equals(SEVEN))
		{
			s = BigInteger.ONE;
		}
		// n % 8 in {3, 5}
		else if (temp.equals(THREE) || temp.equals(FIVE))
		{
			s = NEG_ONE;
		}

		if (n.mod(FOUR).equals(THREE) && a1.mod(FOUR).equals(THREE))
		{
			s = s.multiply(NEG_ONE);
		}
		BigInteger n1 = n.mod(a1);
		if (a1.equals(BigInteger.ONE))
		{
			return s;
		}
		else
		{
			return s.multiply(jacobi(n1, a1));
		}
	}

	public static BigInteger quadratic_non_residue(BigInteger p)
	{
		BigInteger a = BigInteger.ZERO;
		while (!NTL.jacobi(a, p).equals(NEG_ONE))
		{
			// a = randint(1, p) --> [1, p]
			// x = pseudo-random number in the range [0..n-1]
			a = NTL.RandomBnd(p);
		}
		return a;
	}
}