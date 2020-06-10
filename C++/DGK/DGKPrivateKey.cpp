#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

class DGKPrivateKey
{
public:
    // Private Key Parameters
    ZZ p;
    ZZ q;
    ZZ vp;
    ZZ vq;
    //protected final Map <BigInteger, Long> LUT;
    
    // Public key parameters
    ZZ n;
    ZZ g;
    ZZ h;
    long u;
    ZZ bigU;
	
	// Key Parameters
    int l;
    int t;
    int k;
    
    // Signature
    ZZ v;
    
    // Original DGK Private Key Constructor
    DGKPrivateKey (ZZ p, ZZ q, ZZ vp,
                          ZZ vq, DGKPublicKey * pubKey)
    {
    	// Fill Private Key Parameters
    	this -> p = p;
        this -> q = q;
        this -> vp = vp;
        this -> vq = vq;
        this -> v = vp.multiply(vq);
        
        // Public Key Parameters
    	this -> n = pubKey -> n;
    	this -> g = pubKey -> g;
    	this -> h = pubKey -> h;
        this -> u = pubKey -> u;
    	this -> bigU = pubKey -> bigU;
    	
    	// Key Parameters
    	this.l = pubKey -> l;
    	this.t = pubKey -> t;
    	this.k = pubKey -> k;
    	
    	// I already know the size of my map, so just initialize the size now to avoid memory waste!
    	//this.LUT = new HashMap<BigInteger, Long>((int) this.u, (float) 1.0);
    	
    	// Now that I have public key parameters, build LUT!
    	//this.generategLUT();
    }

    private:
    void generategLUT()
    {
        ZZ gvp = AddMod(PowerMod(g, vp, p), p);
        for (ZZ i = 0; i < u; ++i)
        {
            ZZ decipher = PowerMod(gvp, i, p);
            //this.LUT.put(decipher, i);
        }
    }

}
