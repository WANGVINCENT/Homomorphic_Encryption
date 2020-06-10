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
    DGKPrivateKey (ZZ p, ZZ q, ZZ vp, ZZ vq, DGKPublicKey pubKey);


    private:
    void generategLUT();

}
