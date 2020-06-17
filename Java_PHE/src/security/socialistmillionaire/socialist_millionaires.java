package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.generic.NTL;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

public abstract class socialist_millionaires 
{
	protected final static BigInteger TWO = new BigInteger("2");
	protected final SecureRandom rnd = new SecureRandom();
	protected final static int SIGMA = 80;
	protected final static int BILLION = BigInteger.TEN.pow(9).intValue();
	
	// Ensure Alice and Bob have the same settings!
	// May enable users to set this at Runtime?
	protected boolean USE_PROTOCOL_2 = false;
	protected boolean FAST_DIVIDE = false;
    protected boolean isDGK = false;
    
    // Both Alice and Bob will have keys
	protected PaillierPublicKey pk = null;
	protected DGKPublicKey pubKey = null;
	protected ElGamalPublicKey e_pk = null;
	
	// Key Master
	protected PaillierPrivateKey sk = null;
	protected DGKPrivateKey privKey = null;
	protected ElGamalPrivateKey e_sk = null;
	
	// Both use 2^l
	protected BigInteger powL;

	// I/O
	protected ObjectOutputStream toAlice = null;
	protected ObjectInputStream fromAlice = null;
	
	protected ObjectOutputStream toBob = null;
	protected ObjectInputStream fromBob = null;
	
	// Needed for comparison
	protected BigInteger [] toSort = null;
	protected BigInteger [] sortedArray = null;
	protected BigInteger [] tempBigMerg = null;

	public void setSorting(List<BigInteger> toSort)
	{
		this.toSort = toSort.toArray(new BigInteger[toSort.size()]);
	}

	public void setSorting(BigInteger [] toSort)
	{
		this.toSort = toSort;
	}

	public BigInteger [] getSortedArray()
	{
		return sortedArray;
	}

	// Set Methods
	public void setProtocol2(boolean isProtocol2)
	{
		this.USE_PROTOCOL_2 = isProtocol2;
	}

	public void setFastDivide(boolean FAST_DIVIDE)
	{
		this.FAST_DIVIDE = FAST_DIVIDE;
	}

	public void setDGKMode(boolean isDGK)
	{
		this.isDGK = isDGK;
	}

	// Get Methods
	public boolean getProtocol2()
	{
		return USE_PROTOCOL_2;
	}

	public boolean getFastDivide()
	{
		return FAST_DIVIDE;
	}

	public boolean isDGK()
	{
		return isDGK;
	}

	// Get PublicKey
	public PaillierPublicKey getPaillierPublicKey()
	{
		return pk;
	}

	public DGKPublicKey getDGKPublicKey()
	{
		return pubKey;
	}

	public ElGamalPublicKey getElGamalPublicKey()
	{
		return e_pk;
	}
	
	// Get Private Key
	public PaillierPrivateKey getPaillierPrivateKey()
	{
		return sk;
	}

	public DGKPrivateKey getDGKPrivateKey()
	{
		return privKey;
	}

	public ElGamalPrivateKey getElGamalPrivateKey()
	{
		return e_sk;
	}
	
	// Used to shuffle the encrypted bits
	// NOTE THIS METHOD DOES NOT ALLOCATE A NEW ARRAY!
	// SO BE CAREFUL WITH POINTER MANAGEMENT HERE!
	protected BigInteger [] shuffle_bits(BigInteger [] array)
	{
		for (int i = 0; i < array.length; i++) 
		{
			int randomPosition = rnd.nextInt(array.length);
			BigInteger temp = array[i];
			array[i] = array[randomPosition];
			array[randomPosition] = temp;
		}
		return array;
	}
	
	//public abstract boolean Modified_Protocol3(BigInteger x) throws IOException, ClassNotFoundException, IllegalArgumentException;
	
	// -------------------Alice-----------------------------------------------
	// -------------------Protocol 3 and Modified Protocol 3------------------
	
	/*
	 * Input Alice: x (unencrypted BigInteger x)
	 * Input Bob: y (unencrypted BigInteger y), Private Keys
	 * 
	 * Result: [[x <= y]] or [x <= y]
	 * Alice and Bob WITHOUT revealing x, y
	 * It is boolean value! 
	 * x <= y -> [[1]]
	 * x > y -> [[0]]
	 */
	protected boolean Protocol3(BigInteger x, int deltaA)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(x.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}

		Object in = null;
		BigInteger [] XOR = null;
		BigInteger [] C = null;
		BigInteger [] Encrypted_Y = null;
		int deltaB = -1;
		int answer = -1;

		//Step 1: Receive y_i bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
		}

		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		// Case 1, delta B is ALWAYS INITIALIZED TO 0
		// y has more bits -> y is bigger
		if (x.bitLength() < Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			// x <= y -> 1 (true)
			return true;
		}

		// Case 2 delta B is 0
		// x has more bits -> x is bigger
		else if(x.bitLength() > Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			// x <= y -> 0 (false)
			return false;
		}

		// if equal bits, proceed!
		// Step 2: compute Encrypted X XOR Y
		XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = Encrypted_Y[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
			}
		}

		// Step 3: delta A is computed on initialization, it is 0 or 1.

		// Step 4A: Generate C_i, see c_{-1} to test for equality!
		// Step 4B: alter C_i using Delta A
		// C_{-1} = C_i[yBits], will be computed at the end...
		C = new BigInteger [Encrypted_Y.length + 1];

		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			C[i] = DGKOperations.sum(pubKey, XOR, Encrypted_Y.length - 1 - i);
			if (deltaA == 0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				// Step 4 = [c_i] - [y_i bit] + [1]
				C[i] = DGKOperations.subtract(pubKey, C[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], 1);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C[i]= DGKOperations.add(pubKey, C[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
			}
		}

		// This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.add_plaintext(pubKey, C[Encrypted_Y.length], deltaA);

		// Step 5: Apply the Blinding to C_i and send it to Bob
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(NTL.bit(x, i) != deltaA)
			{
				C[Encrypted_Y.length - 1 - i] = DGKOperations.encrypt(pubKey, rnd.nextInt(pubKey.getL()) + 1);
			}
		}
		// Blind and Shuffle bits!
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.getL()) + 1);
		}
		toBob.writeObject(C);
		toBob.flush();

		// Step 7: Obtain Delta B from Bob
		deltaB = fromBob.readInt();

		// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		// 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
		else
		{
			answer = 1;
		}

		/*
		 * Step 8: Bob has the Private key anyways...
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 */
		toBob.writeObject(DGKOperations.encrypt(pubKey, BigInteger.valueOf(answer)));
		toBob.flush();
		return answer == 1;
	}
	
	// Modified Protocol 3 for Protocol 4
	// This should mostly use ONLY DGK stuff!
	protected boolean Modified_Protocol3(BigInteger alpha, BigInteger r, int deltaA) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		int answer = -1;
		Object in = null;
		BigInteger [] beta_bits = null;
		BigInteger [] encAlphaXORBeta = null;
		BigInteger [] w = null;
		BigInteger [] C = null;
		BigInteger alpha_hat = null;
		BigInteger d = null;
		BigInteger N = null;
		long exponent;

		// Get N from size of Plain-text space
		if(isDGK)
		{
			N = pubKey.getU();
		}
		else
		{
			N = pk.getN();
		}

		// Step A: get d from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			d = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger: d not found!");
		}

		// Step B: get beta_bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			beta_bits = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger []: C not found!");
		}

		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		if (alpha.bitLength() < beta_bits.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			return true;
		}
		else if(alpha.bitLength() > beta_bits.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return false;
		}

		// Step C: Alice corrects d...
		if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
		}

		// Step D: Compute alpha_bits XOR beta_bits
		encAlphaXORBeta = new BigInteger[beta_bits.length];
		for (int i = 0; i < encAlphaXORBeta.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(alpha, i) == 0)
			{
				encAlphaXORBeta[i] = beta_bits[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				encAlphaXORBeta[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), beta_bits[i]);				
			}
		}

		// Step E: Compute Alpha Hat
		alpha_hat = r.subtract(N).mod(powL);
		w = new BigInteger[beta_bits.length];

		for (int i = 0; i < beta_bits.length;i++)
		{
			if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
			{
				w[i] = encAlphaXORBeta[i];
			}
			else
			{
				w[i] = DGKOperations.subtract(pubKey, encAlphaXORBeta[i], d);
			}
		}

		// Step F: See Optimization 1
		for (int i = 0; i < beta_bits.length;i++)
		{
			// If it is 16 or 32 bits...
			if(pubKey.getL() % 16 == 0)
			{
				if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
				{
					w[i] = DGKOperations.multiply(pubKey, w[i], pubKey.getL());	
				}
			}
			else
			{
				if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
				{
					w[i] = DGKOperations.multiply(pubKey, w[i], powL);	
				}
			}
		}

		// Step G: Delta A computed at start!

		// Step H: See Optimization 2
		C = new BigInteger[beta_bits.length + 1];
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(deltaA != NTL.bit(alpha, i) && deltaA != NTL.bit(alpha_hat, i))
			{
				// C[i] = DGKOperations.encrypt(pubKey, NTL.RandomBnd(pubKey.getU()));
				// Blinding should take care of the rest!
				C[i] = pubKey.ONE();
			}
			else
			{
				exponent = NTL.bit(alpha_hat, i) - NTL.bit(alpha, i);
				C[i] = DGKOperations.multiply(pubKey, DGKOperations.sum(pubKey, w, i), 3);
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], 1 - (2* deltaA));
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], NTL.bit(alpha, i));
				C[i] = DGKOperations.add(pubKey, C[i], DGKOperations.multiply(pubKey, d, exponent));
				C[i] = DGKOperations.subtract(pubKey, C[i], beta_bits[i]);
			}
		}

		//This is c_{-1}
		C[beta_bits.length] = DGKOperations.sum(pubKey, encAlphaXORBeta);
		C[beta_bits.length] = DGKOperations.add_plaintext(pubKey, C[beta_bits.length], deltaA);

		// Step I: SHUFFLE BITS AND BLIND WITH EXPONENT
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.getU().intValue()) + 1);
		}
		toBob.writeObject(C);
		toBob.flush();

		// Step J: Bob checks whether a C_i has a zero or not...get delta B.
		int deltaB = fromBob.readInt();
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		else
		{
			answer = 1;
		}
		toBob.writeObject(DGKOperations.encrypt(pubKey, answer));
		toBob.flush();
		return answer == 1;
	}
	
	// -------------------Bob-------------------------------------------------
	// -------------------Protocol 3 and Modified Protocol 3------------------

	/*
	 * Input Alice: x (unencrypted BigInteger x)
	 * Input Bob: y (unencrypted BigInteger y), Private Keys
	 * 
	 * Result: 
	 * Alice and Bob WITHOUT revealing x, y know
	 * 0 -> x <= y
	 * 1 -> x > y
	 */

	protected boolean Protocol3(BigInteger y)
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		// Constraint...
		if(y.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
		}
		Object x = null;
		BigInteger [] C = null;
		int deltaB = 0;
		BigInteger deltaA = null;

		//Step 1: Bob sends encrypted bits to Alice
		BigInteger EncY[] = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++)
		{
			EncY[i] = DGKOperations.encrypt(pubKey, NTL.bit(y, i));
		}
		toAlice.writeObject(EncY);
		toAlice.flush();

		//Step 2: Wait for Alice to compute x XOR y

		//Step 3: Wait for Alice to compute set L and gamma A

		//Step 4: Wait for Alice to compute the array of C_i

		//Step 5: After blinding, Alice sends C_i to Bob

		//Step 6: Bob checks if there is a 0 in C_i and seta deltaB accordingly

		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		x = fromAlice.readObject();
		// Number of bits are the same for both numbers
		if (x instanceof BigInteger [])
		{
			C = (BigInteger []) x;
			for (BigInteger C_i: C)
			{
				if (DGKOperations.decrypt(privKey, C_i) == 0)
				{
					deltaB = 1;
					break;
				}
			}
		}
		// Number of bits gives away the answer!
		else if (x instanceof BigInteger)
		{
			deltaA = (BigInteger) x;
			// Case 1 delta B is 0
			// 1 XOR 0 = 0
			// x <= y -> 1 (true)

			// Case 2, delta B is 0
			// 0 XOR 0 = 0
			// x <= y -> 0 (false)
			return deltaA.intValue() == 1;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3, Step 4: Invalid object!");
		}

		// Step 7: Return Gamma B to Alice, Alice will compute GammaA XOR GammaB
		toAlice.writeInt(deltaB);
		toAlice.flush();

		// Step 8: UNOFFICIAL
		// Alice sends the answer, decrypt it and keep it for yourself
		// This is best used in situations like an auction where Bob needs to know
		x = fromAlice.readObject();
		if (x instanceof BigInteger)
		{
			return DGKOperations.decrypt((BigInteger) x, privKey).intValue() == 1;
		}
		else
		{
			throw new IllegalArgumentException("Invalid response from Alice in Step 8!");
		}
	}
	
	// Use this for Using Modified Protocol3 within Protocol 4
	protected boolean Modified_Protocol3(BigInteger beta, BigInteger z) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		BigInteger [] C = null;
		BigInteger [] beta_bits = new BigInteger[beta.bitLength()];
		BigInteger deltaA = null;
		BigInteger d = null;
		BigInteger N = null;
		int answer = -1;
		int deltaB = 0;

		if(isDGK)
		{
			N = pubKey.getU();
		}
		else
		{
			N = pk.getN();
		}

		// Step A: z < (N - 1)/2
		if(z.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ONE);
		}
		else
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
		}
		toAlice.writeObject(d);
		toAlice.flush();

		// Step B: Send the encrypted Beta bits
		for (int i = 0; i < beta_bits.length;i++)
		{
			beta_bits[i] = DGKOperations.encrypt(pubKey, NTL.bit(beta, i));
		}
		toAlice.writeObject(beta_bits);
		toAlice.flush();

		// Step C: Alice corrects d...

		// Step D: Alice computes [[alpha XOR beta]]

		// Step E: Alice Computes alpha_hat and w_bits

		// Step F: Alice Exponentiates w_bits

		// Step G: Alice picks Delta A

		// Step H: Alice computes C_i

		// Step I: Alice blinds C_i

		// Step J: Get C_i and look for zeros
		in = fromAlice.readObject();
		if(in instanceof BigInteger[])
		{
			C = (BigInteger []) in;
		}
		else if (in instanceof BigInteger)
		{
			deltaA = (BigInteger) in;
			return deltaA.intValue() == 1;
		}
		else
		{
			throw new IllegalArgumentException("Modified Protocol3: invalid input in Step J");
		}

		for (BigInteger C_i: C)
		{
			if(DGKOperations.decrypt(privKey, C_i) == 0)
			{
				deltaB = 1;
				break;
			}
		}
		toAlice.writeInt(deltaB);
		toAlice.flush();

		// Extra step...Bob gets the answer from Alice
		in = fromAlice.readObject();
		if(in instanceof BigInteger)
		{
			answer = DGKOperations.decrypt((BigInteger) in, privKey).intValue();
		}
		else
		{
			throw new IllegalArgumentException("Modified_Protocol 3, Step 8 Invalid Object!");
		}
		toAlice.flush();
		return answer == 1;
	}
}
