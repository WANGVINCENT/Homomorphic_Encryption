#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class PaillierPrivateKey
{
	private:
	int key_size;

	ZZ n;
	ZZ modulus;
	ZZ g;

	ZZ lambda;
	ZZ mu;
	
	ZZ rho;
	ZZ alpha;
	
	public:

	PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
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

	int get_Keysize() 
	{
		return key_size;
	}

	BigInteger getModulus() 
	{
		return modulus;
	}
	
    BigInteger getN()
    {
    	return n;
    }
}
