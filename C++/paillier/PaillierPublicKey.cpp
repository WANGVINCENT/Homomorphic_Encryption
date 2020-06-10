

// Check
// package org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

public final class PaillierPublicKey implements Serializable, PaillierKey, PublicKey
{
// k1 is the security parameter. It is the number of bits in n.
	public final int keysize;
	
	// n = pq is a product of two large primes (such N is known as RSA modulous)
    ZZ n;
    ZZ modulus;
    ZZ g;
    
    public PaillierPublicKey(int keysize, BigInteger n, BigInteger modulus, BigInteger g)
    {
    	this.keysize = keysize;
    	this.n = n;
    	this.modulus = modulus;
        this.g = g;
    }
    
    public BigInteger getN()
    {
    	return n;
    }
    
	public BigInteger getModulus() 
	{
		return modulus;
	}
}
