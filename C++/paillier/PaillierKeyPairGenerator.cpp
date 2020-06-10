#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;


class PaillierKeyPairGenerator
{
	private:
	int keysize = 1024;
	SecureRandom rnd = null;

	// Find the smallest divisor!
    	// Find alpha
	// alpha | lcm(p - 1, q - 1)
	static BigInteger find_alpha(BigInteger LCM, BigInteger modulus) 
	{
		BigInteger alpha = TWO;
		while(true)
		{
			if(LCM.mod(alpha).compareTo(BigInteger.ZERO) == 0)
			{
				return alpha;
			}
			alpha = alpha.add(BigInteger.ONE);
		}
	}
	
	// Build generator
	static BigInteger find_g(BigInteger g, BigInteger lambda, BigInteger modulus, BigInteger n)
	{
		while(true)
		{
			if(PaillierCipher.L(g.modPow(lambda, modulus), n).gcd(n).equals(BigInteger.ONE))
			{
				return g;		
			}
			g = g.add(BigInteger.ONE);
		}
	}

	public:
	
	void initialize(int keysize, SecureRandom random) 
	{
		this.rnd = random;
		if (keysize % 2 != 0)
		{
			throw new IllegalArgumentException("NUMBER OF BITS SHOULD BE EVEN!");
		}	
		this.keysize = keysize;
	}

	KeyPair generateKeyPair() 
	{
		// Chooses a random prime of length k2. The probability that
		// p is not prime is at most 2^(-k2)
		ZZ p;
		ZZ q;
		ZZ n;
		ZZ modulus;
		ZZ lambda;
		ZZ mu;
		ZZ g;
		ZZ gcd;
		ZZ alpha;

		GenPrime(p, keysize/2);
		GenPrime(q, keysize/2);

		mul(n, p, q)
		mul(&modulus, &n, &n) // modulous = n^2
		
		// Modifications to the Private key
		--p;
		--q;
		gcd = gcd(p, q);
		lambda = p * q;
		mu = InvMod(lambda, n);

		// For signature
		// Build base g \in Z_{n^2} with order n
		g = TWO;
		g = find_g(g, lambda, modulus, n);
		
		// Beware of flaw with Paillier if g^{lambda} = 1 (mod n^2)
		while(g.modPow(lambda, modulus).equals(BigInteger.ONE))
		{
			g = find_g(g.add(BigInteger.ONE), lambda, modulus, n);
		}
		
		
		alpha = find_alpha(lambda.divide(gcd), modulus);
		
		PaillierPublicKey pk = new PaillierPublicKey(this.keysize, n, modulus, g);
		PaillierPrivateKey sk = new PaillierPrivateKey(this.keysize, n, modulus, lambda, mu, g, alpha);
		
		return new KeyPair(pk, sk);
	}
}
