package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.generic.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierPrivateKey;

/**
Credits to Andrew Quijano and Dr. Samet Tonyali

Alice has [[x]] and [[y]]
Bob has the DGK and Paillier Public Keys

Terms of Use:
Feel free to use this code as you like.

DGK was created in 2007 by:
Ivan Damgard, Martin Geisler, and Mikkel Kroigaard (DGK).

Title of Papers: (Source of Protocol 1, Protocol 2)
Efficient and Secure Comparison for On-Line auctions (2007)
A correction to Efficient and Secure Comparison for Online auctions (2009)

Protocol 3 and Protocol 4 was created referencing Thjis Veugen's Paper:
Improving the DGK Comparison Protocol (2012)
 */

public final class bob extends socialist_millionaires implements Runnable
{	
	// YOU SHOULD USE THIS CONSTRUCTOR!
	public bob (Socket clientSocket,
			KeyPair a, KeyPair b) throws IOException, IllegalArgumentException
	{
		this(clientSocket, a, b, null, false);
	}

	// YOU SHOULD USE THIS CONSTRUCTOR!
	public bob (Socket clientSocket,
			KeyPair a, KeyPair b, KeyPair c) throws IOException, IllegalArgumentException
	{
		this(clientSocket, a, b, c, false);
	}

	public bob (Socket clientSocket,
			KeyPair a, KeyPair b, boolean IS_DEBUG) throws IOException, IllegalArgumentException
	{
		this(clientSocket, a, b, null, IS_DEBUG);
	}

	public bob (Socket clientSocket,
			KeyPair a, KeyPair b, KeyPair c, boolean IS_DEBUG) 
					throws IOException, IllegalArgumentException
	{
		if(clientSocket != null)
		{
			this.fromAlice = new ObjectInputStream(clientSocket.getInputStream());
			this.toAlice = new ObjectOutputStream(clientSocket.getOutputStream());
		}
		else
		{
			throw new NullPointerException("Client Socket is null!");
		}

		if (a.getPublic() instanceof PaillierPublicKey)
		{
			this.pk = (PaillierPublicKey) a.getPublic();
			this.sk = (PaillierPrivateKey) a.getPrivate();
			if(b.getPublic() instanceof DGKPublicKey)
			{
				this.pubKey = (DGKPublicKey) b.getPublic();
				this.privKey = (DGKPrivateKey) b.getPrivate();
			}
			else
			{
				throw new IllegalArgumentException("Obtained Paillier Key Pair, Not DGK Key pair!");
			}
		}
		else if (a.getPublic() instanceof DGKPublicKey)
		{
			this.pubKey = (DGKPublicKey) a.getPublic();
			this.privKey = (DGKPrivateKey) a.getPrivate();
			if (b.getPublic() instanceof PaillierPublicKey)
			{
				this.pk = (PaillierPublicKey) a.getPublic();
				this.sk = (PaillierPrivateKey) a.getPrivate();
			}
			else
			{
				throw new IllegalArgumentException("Obtained DGK Key Pair, Not Paillier Key pair!");
			}
		}

		if(c != null)
		{
			// IF YOU GIVE BOB A THIRD KEY PAIR, IT MUST BE EL GAMAL!
			if (c.getPublic() instanceof ElGamalPublicKey)
			{
				this.e_pk = (ElGamalPublicKey) c.getPublic();
				this.e_sk = (ElGamalPrivateKey) c.getPrivate();
			}
			else
			{
				throw new IllegalArgumentException("Third Keypair MUST BE AN EL GAMAL KEY PAIR!");
			}
		}

		this.sendPublicKeys();
		this.isDGK = false;
		powL = TWO.pow(pubKey.getL());

		if(IS_DEBUG)
		{
			this.debug();
		}
	}

	// This is used for Alice to sort an array of encryped numbers!
	private void repeat_Protocol2()
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		long start_time = System.nanoTime();
		int counter = 0;
		while(fromAlice.readBoolean())
		{
			++counter;
			//System.out.println("Iteration " + counter);
			this.Protocol2();
		}
		System.out.println("Protocol 2 was used " + counter + " times!");
		System.out.println("Protocol 2 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
	}

	// This is used for Alice to sort an array of encrypted numbers!
	private void repeat_Protocol4()
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		long start_time = System.nanoTime();
		int counter = 0;
		while(fromAlice.readBoolean())
		{
			++counter;
			this.Protocol4();
		}
		if(isDGK)
		{
			System.out.println("DGK Protocol 4 was used " + counter + " times!");
			System.out.println("DGK Protocol 4 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");			
		}
		else
		{
			System.out.println("Paillier Protocol 4 was used " + counter + " times!");
			System.out.println("Paillier Protocol 4 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
		}
	}

	public boolean Protocol1(BigInteger y) throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		// Constraint...
		if(y.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
		}

		Object in = null;
		int deltaB = 0;
		BigInteger deltaA = null;
		BigInteger [] C = null;

		//Step 1: Bob sends encrypted bits to Alice
		BigInteger [] EncY = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++)
		{
			EncY[i] = DGKOperations.encrypt(pubKey, NTL.bit(y, i));
		}
		toAlice.writeObject(EncY);
		toAlice.flush();

		// Step 2: Alice...

		// Step 3: Alice...

		// Step 4: Alice...

		// Step 5: Alice...

		// Step 6: Check if one of the numbers in C_i is decrypted to 0.
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
			throw new IllegalArgumentException("Protocol 1, Step 6: Invalid object!");
		}

		for (BigInteger C_i: C)
		{
			if (DGKOperations.decrypt(privKey, C_i) == 0)
			{
				deltaB = 1;
				break;
			}
		}

		// Step 7: UNOFFICIAL
		// Inform Alice what deltaB is
		toAlice.writeInt(deltaB);
		toAlice.flush();

		// Step 8: UNOFFICIAL
		// Alice sends the answer, decrypt it and keep it for yourself
		// This is best used in situations like an auction where Bob needs to know
		in = fromAlice.readObject();
		if (in instanceof BigInteger)
		{
			return DGKOperations.decrypt((BigInteger) in, privKey).intValue() == 1;
		}
		else
		{
			throw new IllegalArgumentException("Invalid response from Alice in Step 8!");
		}
	}

	// NOTE: AS STATED IN CORRECTION PAPER
	// THIS COMPUTES [[X >= Y]] NOT [X <= Y]]
	public boolean Protocol2() throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		// Step 1: Receive z from Alice
		// Get the input and output streams
		int answer = -1;
		Object x = null;
		BigInteger beta = null;
		BigInteger z = null;

		if(isDGK)
		{
			System.err.println("COMPARING ENCRYPTED DGK VALUES WITH PROTOCOL 2 IS NOT ALLOWED, PLEASE USE PROTOCOL 4!");
			return answer == 1;
		}

		//Step 1: get [[z]] from Alice
		x = fromAlice.readObject();
		if (x instanceof BigInteger)
		{
			z = (BigInteger) x;
		}
		else
		{
			throw new IllegalArgumentException("Bob Step 1: Obtaining Z failed!");
		}

		//[[z]] = [[x - y + 2^l + r]]
		z = PaillierCipher.decrypt(z, sk);


		// Step 2: compute Beta = z (mod 2^l),
		beta = NTL.POSMOD(z, powL);

		// Step 3: Alice computes r (mod 2^l) (Alpha)
		// Step 4: Run Protocol 3
		Protocol3(beta);

		// Step 5: Send [[z/2^l]], Alice has the solution from Protocol 3 already...
		toAlice.writeObject(PaillierCipher.encrypt(z.divide(powL), pk));
		toAlice.flush();

		// Step 6 - 7: Alice Computes [[x <= y]]

		// Step 8 (UNOFFICIAL): Alice needs the answer for [[x <= y]]
		x = fromAlice.readObject();
		if (x instanceof BigInteger)
		{
			answer = PaillierCipher.decrypt((BigInteger) x, sk).intValue();
			toAlice.writeInt(answer);
			toAlice.flush();
			return answer == 1;
		}
		else
		{
			throw new IllegalArgumentException("No response from Alice in Step 8!");
		}
	}
	
	public boolean Protocol3(BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException 
	{
		return Protocol3(y);
	}

	// Used for Regular Modified Protocol 3 ONLY 
	public boolean Modified_Protocol3(BigInteger z) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		BigInteger beta = null;
		boolean answer;

		// Constraint...
		if(z.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + z.bitLength() + " bits");
		}
		if(isDGK)
		{
			beta = z.mod(powL);
			answer = Modified_Protocol3(beta, z);
		}
		else
		{
			isDGK = true;
			beta = z.mod(powL);
			answer = Modified_Protocol3(beta, z);
			isDGK = false;
		}
		return answer;
	}

	
	public boolean Protocol4() 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		// Constraint for Paillier
		if(!isDGK && pubKey.getL() + 2 >= pk.keysize)
		{
			throw new IllegalArgumentException("Constraint violated: l + 2 < log_2(N)");
		}

		int answer = -1;
		Object x = null;
		BigInteger beta = null;
		BigInteger z = null;
		BigInteger zeta_one = null;
		BigInteger zeta_two = null;

		//Step 1: get [[z]] from Alice
		x = fromAlice.readObject();;
		if (x instanceof BigInteger)
		{
			z = (BigInteger) x;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4: No BigInteger found!");
		}

		if(isDGK)
		{
			z = BigInteger.valueOf(DGKOperations.decrypt(privKey, z));
		}
		else
		{
			z = PaillierCipher.decrypt(z, sk);
		}

		// Step 2: compute Beta = z (mod 2^l), 
		beta = NTL.POSMOD(z, powL);

		// Step 3: Alice computes r (mod 2^l) (Alpha)

		// Step 4: Run Modified DGK Comparison Protocol
		// true --> run Modified protocol 3
		if(fromAlice.readBoolean())
		{
			Modified_Protocol3(beta, z);
		}
		else
		{
			Protocol3(beta);
		}

		//Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already..
		if(isDGK)
		{
			zeta_one = DGKOperations.encrypt(pubKey, z.divide(powL));
			if(z.compareTo(pubKey.getU().subtract(BigInteger.ONE).divide(TWO)) == -1)
			{
				zeta_two = DGKOperations.encrypt(pubKey, z.add(pubKey.getU()).divide(powL));
			}
			else
			{
				zeta_two = DGKOperations.encrypt(pubKey, z.divide(powL));
			}
		}
		else
		{
			zeta_one = PaillierCipher.encrypt(z.divide(powL), pk);
			if(z.compareTo(pk.getN().subtract(BigInteger.ONE).divide(TWO)) == -1)
			{
				zeta_two = PaillierCipher.encrypt(z.add(pubKey.getN()).divide(powL), pk);
			}
			else
			{
				zeta_two =  PaillierCipher.encrypt(z.divide(powL), pk);
			}
		}
		toAlice.writeObject(zeta_one);
		toAlice.writeObject(zeta_two);
		toAlice.flush();

		//Step 6 - 7: Alice Computes [[x >= y]]

		//Step 8 (UNOFFICIAL): Alice needs the answer...
		x = fromAlice.readObject();
		if (x instanceof BigInteger)
		{
			if(isDGK)
			{
				answer = DGKOperations.decrypt((BigInteger) x, privKey).add(BigInteger.ONE).mod(pubKey.getU()).intValue();
			}
			else
			{
				answer = PaillierCipher.decrypt((BigInteger) x, sk).intValue();
			}
			toAlice.writeInt(answer);
			toAlice.flush();	
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 8 Failed");
		}
		return answer == 1;
	}

	public void division(long divisor) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		BigInteger c = null;
		BigInteger z = null;
		Object alice = fromAlice.readObject();
		if(alice instanceof BigInteger)
		{
			z = (BigInteger) alice;
		}
		else
		{
			throw new IllegalArgumentException("Divison: No BigInteger found!");
		}

		if(isDGK)
		{
			z = BigInteger.valueOf(DGKOperations.decrypt(privKey, z));
		}
		else
		{
			z = PaillierCipher.decrypt(z, sk);
		}

		if(!FAST_DIVIDE)
		{
			Protocol3(z.mod(BigInteger.valueOf(divisor)));
		}
		// MAYBE IF OVER FLOW HAPPENS?
		// Modified_Protocol3(z.mod(powL), z);	

		c = z.divide(BigInteger.valueOf(divisor));
		if(isDGK)
		{
			toAlice.writeObject(DGKOperations.encrypt(pubKey, c));	
		}
		else
		{
			toAlice.writeObject(PaillierCipher.encrypt(c, pk));
		}
		toAlice.flush();
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not leak the numbers themselves, 
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}

	public void multiplication() 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		BigInteger x_prime = null;
		BigInteger y_prime = null;

		// Step 2
		in = fromAlice.readObject();
		if(in instanceof BigInteger)
		{
			x_prime = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x']] from Alice");
		}

		in = fromAlice.readObject();
		if(in instanceof BigInteger)
		{
			y_prime = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[y']] from Alice");		
		}

		// Step 3
		if(isDGK)
		{
			x_prime = DGKOperations.decrypt(x_prime, privKey);
			y_prime = DGKOperations.decrypt(y_prime, privKey);
			// To avoid myself throwing errors of encryption must be [0, U), mod it now!
			toAlice.writeObject(DGKOperations.encrypt(pubKey, x_prime.multiply(y_prime).mod(pubKey.getU())));
		}
		else
		{
			x_prime = PaillierCipher.decrypt(x_prime, sk);
			y_prime = PaillierCipher.decrypt(y_prime, sk);
			// To avoid myself throwing errors of encryption must be [0, N), mod it now!
			toAlice.writeObject(PaillierCipher.encrypt(x_prime.multiply(y_prime).mod(pk.getN()), pk));
		}
		toAlice.flush();
	}

	public void sendPublicKeys() throws IOException
	{
		if(pubKey != null)
		{
			toAlice.writeObject(pubKey);
		}
		else
		{
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(pk != null)
		{
			toAlice.writeObject(pk);	
		}
		else
		{
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(e_pk != null)
		{
			toAlice.writeObject(e_pk);
		}
		else
		{
			toAlice.writeObject(BigInteger.ZERO);
		}
		toAlice.flush();
	}

	protected void debug() throws IOException
	{
		toAlice.writeObject(privKey);
		toAlice.flush();
		toAlice.writeObject(sk);
		toAlice.flush();
		if(e_sk != null)
		{
			toAlice.writeObject(e_sk);
		}
		else
		{
			toAlice.writeObject(BigInteger.ZERO);
		}
		toAlice.flush();
	}

	public void writeObject(Object o) throws IOException
	{
		toAlice.writeObject(o);
		toAlice.flush();
	}

	public Object readObject() throws ClassNotFoundException, IOException
	{
		return fromAlice.readObject();
	}

	
	public void run() 
	{
		try
		{
			if(USE_PROTOCOL_2)
			{
				repeat_Protocol2();
			}
			else
			{
				repeat_Protocol4();
			}
		}
		catch (ClassNotFoundException | IOException | IllegalArgumentException e) 
		{
			e.printStackTrace();
		}
	}
}