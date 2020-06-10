#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class PaillierCipher
{

//-----------------------BigInteger Paillier----------------------------------------------
private:
    // L(u) = (u - 1)/n
    static BigInteger L(BigInteger u, BigInteger n) 
    {
        return u.subtract(BigInteger.ONE).divide(n);
    }

public:
    // Compute ciphertext = (mn+1)r^n (mod n^2) in two stages: (mn+1) and (r^n).
    static BigInteger encrypt(BigInteger plaintext, PaillierPublicKey pk) 
    {
		if (plaintext.signum() == -1)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
					+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext.compareTo(pk.n) >= 0)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in N"
					+ " (plaintext >= N) value of Plain Text is: " + plaintext);
		}
		
        //BigInteger randomness = new BigInteger(pk.keysize, rnd);
        BigInteger randomness = NTL.RandomBnd(pk.n);
        //BigInteger tmp1 = plaintext.multiply(pk.n).add(BigInteger.ONE).mod(pk.modulus);
        BigInteger tmp1 = pk.g.modPow(plaintext, pk.modulus);
        BigInteger tmp2 = randomness.modPow(pk.n, pk.modulus);
        BigInteger ciphertext = NTL.POSMOD(tmp1.multiply(tmp2), pk.modulus);
        return ciphertext;
    }

    // Compute plaintext = L(c^(lambda) mod n^2) * mu mod n
    static BigInteger decrypt(BigInteger ciphertext, PaillierPrivateKey sk)
    {
		if (ciphertext.signum() == -1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		else if (ciphertext.compareTo(sk.modulus) == 1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}
        //BigInteger plaintext = L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.mu).mod(sk.n);
        BigInteger plaintext = L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.rho).mod(sk.n);
        return plaintext;
    }

    // On input two encrypted values, returns an encryption of the sum of the
    // values
    static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk)
    {
        BigInteger ciphertext = ciphertext1.multiply(ciphertext2).mod(pk.modulus);
        return ciphertext;
    }
    
    static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey pk)
    {
        BigInteger new_ciphertext = ciphertext.multiply(pk.g.modPow(plaintext, pk.modulus)).mod(pk.modulus);
        return new_ciphertext;
    }
    
    static BigInteger add_plaintext(BigInteger ciphertext, long plaintext, PaillierPublicKey pk)
    {
        BigInteger new_ciphertext = ciphertext.multiply(pk.g.modPow(BigInteger.valueOf(plaintext), pk.modulus)).mod(pk.modulus);
        return new_ciphertext;
    }
    
    static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk)
    {
    	BigInteger neg_ciphertext2 = PaillierCipher.multiply(ciphertext2, pk.n.subtract(BigInteger.ONE), pk);
		BigInteger ciphertext = ciphertext1.multiply(neg_ciphertext2).mod(pk.modulus);
		return ciphertext;
    }
    
    // On input an encrypted value [[x]] and a scalar c, returns an encryption of [[cx]].
    // For now, I will permit negative number multiplication, especially for SST REU 2017
    static BigInteger multiply(BigInteger ciphertext1, BigInteger scalar, PaillierPublicKey pk)
    {
        BigInteger ciphertext = ciphertext1.modPow(scalar, pk.modulus);
        return ciphertext;
    }

    static BigInteger multiply(BigInteger ciphertext1, long scalar, PaillierPublicKey pk) 
    {
        return multiply(ciphertext1, BigInteger.valueOf(scalar), pk);
    }
    
    
	static BigInteger sum(BigInteger [] values, PaillierPublicKey pk)
	{
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (int i = 0; i < values.length; i++)
		{
			sum = PaillierCipher.add(sum, values[i], pk);
		}
		return sum;
	}
	
	static BigInteger sum(BigInteger [] values, PaillierPublicKey pk, int limit)
	{
		if (limit > values.length)
		{
			return sum(values, pk);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = PaillierCipher.add(sum, values[i], pk);
		}
		return sum;
	}
	
	static BigInteger summation(ArrayList<BigInteger> values, PaillierPublicKey pk)
	{
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (int i = 0; i < values.size(); i++)
		{
			sum = PaillierCipher.add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	static BigInteger summation(ArrayList<BigInteger> values, PaillierPublicKey pk, int limit)
	{
		if (limit > values.size())
		{
			return summation(values, pk);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = PaillierCipher.add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	static BigInteger sum_product (PaillierPublicKey pk, List<BigInteger> cipher, List<Long> plain)
	{
		if(cipher.size() != plain.size())
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.size()];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = PaillierCipher.multiply(cipher.get(i), plain.get(i), pk);
		}
		return sum(product_vector, pk);
	}
	
	static BigInteger sum_product (PaillierPublicKey pk, BigInteger[] cipher, Long[] plain)
	{
		if(cipher.length != plain.length)
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.length];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = PaillierCipher.multiply(cipher[i], plain[i], pk);
		}
		return sum(product_vector, pk);
	}
	/*
	 * Please note: Divide will only work correctly on perfect divisor
	 * 2|20, it will work.
	 * if you try 3|20, it will NOT work and you will get a wrong answer!
	 * 
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 */
	static BigInteger divide(BigInteger ciphertext, long divisor, PaillierPublicKey pk)
	{
		return divide(ciphertext, BigInteger.valueOf(divisor), pk);
	}
	
	static BigInteger divide(BigInteger ciphertext, BigInteger divisor, PaillierPublicKey pk)
	{
		return multiply(ciphertext, divisor.modInverse(pk.modulus), pk);
	}
	
}
