#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;


class DGKPublicKey
{
public:
	ZZ n;
	ZZ g;
	ZZ h;
	long u;
	ZZ bigU;
	//HashMap <Long, BigInteger> gLUT = new HashMap<Long, BigInteger>();
	//HashMap <Long, BigInteger> hLUT = new HashMap<Long, BigInteger>();
	
	// Key Parameters
	int l;
	int t;
	int k;

	//DGK Constructor with ALL parameters
	DGKPublicKey(BigInteger n, BigInteger g, BigInteger h, BigInteger u,
						int l, int t, int k)
	{
		this -> n = n;
		this -> g = g;
		this -> h = h;
		this -> u = u.longValue();
		this -> bigU = u;
		this -> l = l; 
		this -> t = t;
		this -> k = k;
	}
	
private:
	void generatehLUT()
	{		
		for (long i = 0; i < 2 * t; ++i)
		{
			// e = 2^i (mod n)
			// h^{2^i (mod n)} (mod n)
			// f(i) = h^{2^i}(mod n)
			BigInteger e = TWO.pow((int) i).mod(this.n);
			this.hLUT.put(i, this.h.modPow(e, this.n));
		}
	}
	
	void generategLUT()
	{	
		for (long i = 0; i < this.u; ++i)
		{
			ZZ out = this.g.modPow(BigInteger.valueOf(i), this.n);
			// this.gLUT.put(i, out);
		}
	}
}
