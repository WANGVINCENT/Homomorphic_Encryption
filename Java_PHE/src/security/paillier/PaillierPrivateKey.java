package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public final class PaillierPrivateKey implements Serializable, PaillierKey, PrivateKey
{
	private static final long serialVersionUID = -3342551807566493368L;

	// k1 is the security parameter. It is the number of bits in n.
	private final int key_size;

	protected final BigInteger n;
	protected final BigInteger modulus;
	protected final BigInteger g;

	protected final BigInteger lambda;
	protected final BigInteger mu;
	
	protected final BigInteger rho;
	protected final BigInteger alpha;
	
	public PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
			BigInteger lambda, BigInteger mu, BigInteger g, BigInteger alpha)
	{
		this.key_size = key_size;
		this.n = n;
		this.modulus = mod;
		this.lambda = lambda;
		this.mu = mu;
		this.g = g;
		this.alpha = alpha;
		this.rho = PaillierCipher.L(this.g.modPow(this.lambda, this.modulus), this.n).modInverse(this.modulus);
	}

	private void readObject(ObjectInputStream aInputStream) 
			throws ClassNotFoundException, IOException
	{
		aInputStream.defaultReadObject();
	}

	private void writeObject(ObjectOutputStream aOutputStream) throws IOException
	{
		aOutputStream.defaultWriteObject();
	}

	public boolean equals(Object o)
	{
		if (!(o instanceof PaillierPrivateKey))
		{
			return false;
		}

		if (o == this)
		{
			return true;
		}
		PaillierPrivateKey key = (PaillierPrivateKey) o;
		return n.equals(key.n) && modulus.equals(key.modulus) 
				&& lambda.equals(key.lambda) && mu.equals(key.mu);
	}

	// Omitting secret key parameters
	public String toString()
	{
		String answer = "";
		answer += "key_size = " + this.key_size + ", " + '\n';
		answer += "n =        " + this.n + ", " + '\n';
		answer += "modulus =  " + this.modulus + '\n';
		answer += "g =        " + this.g + '\n';
		//answer += "lambda =   " + lambda + '\n';
		//answer += "alpha =    " + this.alpha+ '\n';
		//answer += "mu =       " + mu;
		return answer;
	}

	public int get_Keysize() 
	{
		return key_size;
	}

	public BigInteger getModulus() 
	{
		return modulus;
	}
	
    public BigInteger getN()
    {
    	return n;
    }

	public String getAlgorithm() 
	{
		return "Paillier";
	}

	public String getFormat() 
	{
		return "PKCS#8";
	}
	
	public byte[] getEncoded() 
	{
		return null;
	}
}