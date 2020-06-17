package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;

import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamal_Ciphertext;
import security.generic.NTL;

public class bob_elgamal extends socialist_millionaires
{
	// This is used for Alice to sort an array of encrypted numbers!
	public void repeat_Protocol4()
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		long start_time = System.nanoTime();
		int counter = 0;
		while(fromAlice.readBoolean())
		{
			++counter;
			this.Protocol4();
		}
		System.out.println("ElGamal Protocol 4 was used " + counter + " times!");
		System.out.println("ElGamal Protocol 4 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
	}
	
	public boolean Protocol4() 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		int answer = -1;
		Object x = null;
		BigInteger beta = null;
		BigInteger z = null;
		ElGamal_Ciphertext enc_z = null;
		ElGamal_Ciphertext zeta_one = null;
		ElGamal_Ciphertext zeta_two = null;
		BigInteger N = e_pk.getP().subtract(BigInteger.ONE);
		
		//Step 1: get [[z]] from Alice
		x = fromAlice.readObject();
		if (x instanceof ElGamal_Ciphertext)
		{
			enc_z = (ElGamal_Ciphertext) x;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4: No ElGamal_Ciphertext found!");
		}
		z = ElGamalCipher.decrypt(e_sk, enc_z);
		
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
		zeta_one = ElGamalCipher.encrypt(e_pk, z.divide(powL));
		if(z.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			zeta_two = ElGamalCipher.encrypt(e_pk, z.add(N).divide(powL));
		}
		else
		{
			zeta_two = ElGamalCipher.encrypt(e_pk, z.divide(powL));
		}
		toAlice.writeObject(zeta_one);
		toAlice.writeObject(zeta_two);
		toAlice.flush();

		//Step 6 - 7: Alice Computes [[x >= y]]

		//Step 8 (UNOFFICIAL): Alice needs the answer...
		x = fromAlice.readObject();
		if (x instanceof ElGamal_Ciphertext)
		{
			answer = ElGamalCipher.decrypt(e_sk, (ElGamal_Ciphertext) x).intValue();
			toAlice.writeInt(answer);
			toAlice.flush();
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 8 Failed");
		}
		return answer == 1;
	}
	
	// Support addition and subtraction
	public void addition(boolean addition) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext enc_x_prime = null;
		ElGamal_Ciphertext enc_y_prime = null;
		BigInteger x_prime = null;
		BigInteger y_prime = null;

		// Step 2
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext)
		{
			enc_x_prime = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x']] from Alice");
		}

		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext)
		{
			enc_y_prime = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[y']] from Alice");		
		}

		// Step 3
		x_prime = ElGamalCipher.decrypt(e_sk, enc_x_prime);
		y_prime = ElGamalCipher.decrypt(e_sk, enc_y_prime);
		if(addition)
		{
			toAlice.writeObject(ElGamalCipher.encrypt(e_pk, x_prime.add(y_prime)));	
		}
		else
		{
			toAlice.writeObject(ElGamalCipher.encrypt(e_pk, x_prime.subtract(y_prime)));
		}
		toAlice.flush();
	}
	
	public void multiplication() 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext enc_x_prime = null;
		ElGamal_Ciphertext enc_y_prime = null;
		BigInteger x_prime = null;
		BigInteger y_prime = null;
		
		// Step 2
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext)
		{
			enc_x_prime = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x']] from Alice");
		}
		
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext)
		{
			enc_y_prime = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[y']] from Alice");		
		}
		
		// Step 3
		x_prime = ElGamalCipher.decrypt(e_sk, enc_x_prime);
		y_prime = ElGamalCipher.decrypt(e_sk, enc_y_prime);
		toAlice.writeObject(ElGamalCipher.encrypt(e_pk, x_prime.multiply(y_prime)));
		toAlice.flush();
	}
	
	public void division(long divisor) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		BigInteger c = null;
		BigInteger z = null;
		ElGamal_Ciphertext enc_z = null;
		Object alice = fromAlice.readObject();
		if(alice instanceof ElGamal_Ciphertext)
		{
			enc_z = (ElGamal_Ciphertext) alice;
		}
		else
		{
			throw new IllegalArgumentException("Divison: No ElGamal Ciphertext found!");
		}
	
		z = ElGamalCipher.decrypt(e_sk, enc_z);
		if(!FAST_DIVIDE)
		{
			Protocol3(z.mod(BigInteger.valueOf(divisor)));
		}
		
		c = z.divide(BigInteger.valueOf(divisor));
		toAlice.writeObject(ElGamalCipher.encrypt(e_pk, c));
		toAlice.flush();
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not leak the numbers themselves, 
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}

}
