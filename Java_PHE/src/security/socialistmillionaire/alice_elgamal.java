package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamal_Ciphertext;
import security.generic.CipherConstants;
import security.generic.NTL;

public class alice_elgamal extends socialist_millionaires
{
	public boolean Protocol4(ElGamal_Ciphertext x, ElGamal_Ciphertext y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		if(!e_pk.ADDITIVE)
		{
			throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found!");
		}
		int deltaB = -1;
		int x_leq_y = -1;
		int comparison = -1;
		int deltaA = rnd.nextInt(2);
		Object bob = null;
		ElGamal_Ciphertext alpha_lt_beta = null;
		ElGamal_Ciphertext z = null;
		ElGamal_Ciphertext zeta_one = null;
		ElGamal_Ciphertext zeta_two = null;
		ElGamal_Ciphertext result = null;
		BigInteger r = null;
		BigInteger alpha = null;
		BigInteger N = e_pk.getP().subtract(BigInteger.ONE);

		// Step 1: 0 <= r < N
		r = NTL.RandomBnd(CipherConstants.FIELD_SIZE);

		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		z = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, r.add(powL)), e_pk);
		z = ElGamalCipher.subtract(z, y, e_pk);
		toBob.writeObject(z);
		toBob.flush();

		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Modified Protocol 3 or Protocol 3

		// See Optimization 3: true --> Use Modified Protocol 3 	
		if(r.add(TWO.pow(pubKey.getL() + 1)).compareTo(N) == -1)
		{
			toBob.writeBoolean(false);
			toBob.flush();
			if(Protocol3(alpha, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}
		else
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(Modified_Protocol3(alpha, r, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}

		// Step 5: get Delta B and [[z_1]] and [[z_2]]
		if(deltaA == x_leq_y)
		{
			deltaB = 0;
		}
		else
		{
			deltaB = 1;
		}

		bob = fromBob.readObject();
		if (bob instanceof ElGamal_Ciphertext)
		{
			zeta_one = (ElGamal_Ciphertext) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found!");
		}

		bob = fromBob.readObject();
		if (bob instanceof ElGamal_Ciphertext)
		{
			zeta_two = (ElGamal_Ciphertext) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found!");
		}

		// Step 6: Compute [[beta <= alpha]]
		if(deltaA == 1)
		{
			alpha_lt_beta = ElGamalCipher.encrypt(e_pk, deltaB);
		}
		else
		{
			alpha_lt_beta = ElGamalCipher.encrypt(e_pk, 1 - deltaB);
		}

		// Step 7: Compute [[x <= y]]
		if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			result = ElGamalCipher.subtract(zeta_one, ElGamalCipher.encrypt(e_pk, r.divide(powL)), e_pk);
		}
		else
		{
			result = ElGamalCipher.subtract(zeta_two, ElGamalCipher.encrypt(e_pk, r.divide(powL)), e_pk);
		}
		result = ElGamalCipher.subtract(result, alpha_lt_beta, e_pk);

		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		toBob.flush();
		comparison = fromBob.readInt();
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
			//System.out.println("Invalid Comparison result --> " + comparison);
		}
		return comparison == 1;
	}

	// What to do if you want to subtract two El-Gamal texts?
	public ElGamal_Ciphertext addition(ElGamal_Ciphertext x, ElGamal_Ciphertext y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		if(e_pk.ADDITIVE)
		{
			throw new IllegalArgumentException("ElGamal is NOT additive mode");
		}
		Object in = null;
		ElGamal_Ciphertext x_prime = null;
		ElGamal_Ciphertext y_prime = null;
		BigInteger plain_a = NTL.RandomBnd(pubKey.getU());
		ElGamal_Ciphertext a = ElGamalCipher.encrypt(e_pk, plain_a);
		ElGamal_Ciphertext result = null;

		// Step 1
		x_prime = ElGamalCipher.multiply(x, a, e_pk);
		y_prime = ElGamalCipher.multiply(y, a, e_pk);

		toBob.writeObject(x_prime);
		toBob.flush();

		toBob.writeObject(y_prime);
		toBob.flush();

		// Step 2

		// Step 3
		in = fromBob.readObject();
		if (in instanceof ElGamal_Ciphertext)
		{
			result = (ElGamal_Ciphertext) in;
			result = ElGamalCipher.divide(result, a ,e_pk);
			// Debug...
			if(e_sk != null)
			{
				System.out.println(ElGamalCipher.decrypt(e_sk, result));
			}
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob");
		}
		return result;
	}

	public ElGamal_Ciphertext multiplication(ElGamal_Ciphertext x, ElGamal_Ciphertext y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext result = null;
		ElGamal_Ciphertext x_prime = null;
		ElGamal_Ciphertext y_prime = null;
		BigInteger a = null;
		BigInteger b = null;
		BigInteger N = CipherConstants.FIELD_SIZE;

		// Step 1
		a = NTL.RandomBnd(N);
		b = NTL.RandomBnd(N);
		x_prime = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, a), e_pk);
		y_prime = ElGamalCipher.add(y, ElGamalCipher.encrypt(e_pk, b), e_pk);
		toBob.writeObject(x_prime);
		toBob.flush();

		toBob.writeObject(y_prime);
		toBob.flush();

		// Step 2

		// Step 3
		in = fromBob.readObject();
		if (in instanceof ElGamal_Ciphertext)
		{
			result = (ElGamal_Ciphertext) in;
			result = ElGamalCipher.subtract(result, ElGamalCipher.multiply_scalar(x, b, e_pk), e_pk);
			result = ElGamalCipher.subtract(result, ElGamalCipher.multiply_scalar(y, a, e_pk), e_pk);
			result = ElGamalCipher.subtract(result, ElGamalCipher.encrypt(e_pk, a.multiply(b)), e_pk);
			// Debug...
			if(e_sk != null)
			{
				try
				{
					System.out.println(ElGamalCipher.decrypt(e_sk, result));
				}
				catch(IllegalArgumentException e)
				{
					System.out.println("[[x * y]] is out of scope of plain-text!");
				}
			}
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob");
		}
		return result;
	}

	public ElGamal_Ciphertext division(ElGamal_Ciphertext x, long d) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext answer = null;
		ElGamal_Ciphertext c = null;
		ElGamal_Ciphertext z = null;
		BigInteger r = null;
		int t = 0;

		// Step 1
		r = NTL.generateXBitRandom(16 - 1);
		z = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, r), e_pk);
		toBob.writeObject(z);
		toBob.flush();

		// Step 2: Executed by Bob

		// Step 3: Compute secure comparison Protocol 
		if(!FAST_DIVIDE)
		{
			// FLIP IT
			if(Protocol3(r.mod(BigInteger.valueOf(d))))
			{
				t = 0;
			}
			else
			{
				t = 1;
			}
		}

		// Step 4: Bob computes c and Alice receives it
		in = fromBob.readObject();
		if (in instanceof ElGamal_Ciphertext)
		{
			c = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Alice: BigInteger not found! " + in.getClass());
		}

		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		answer = ElGamalCipher.subtract(c, ElGamalCipher.encrypt(e_pk, r.divide(BigInteger.valueOf(d))), e_pk);
		if(t == 1)
		{
			answer = ElGamalCipher.subtract(answer, ElGamalCipher.encrypt(e_pk, t), e_pk);
		}

		// Print Answer to verify
		if (e_sk != null)
		{
			System.out.println("answer: " + ElGamalCipher.decrypt(e_sk, answer));	
		}
		return answer;
	}

	public List<ElGamal_Ciphertext> getKMin(List<ElGamal_Ciphertext> input, int k) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(k > input.size() || k <= 0)
		{
			throw new IllegalArgumentException("Invalid k value!");
		}
		// deep copy
		List<ElGamal_Ciphertext> arr = new ArrayList<ElGamal_Ciphertext>();
		for(ElGamal_Ciphertext p : input)
		{
			arr.add(p);
		}

		ElGamal_Ciphertext temp;
		List<ElGamal_Ciphertext> min = new ArrayList<ElGamal_Ciphertext>();

		for (int i = 0; i < k; i++)
		{
			for (int j = 0; j < arr.size() - i - 1; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();

				// Originally arr[j] > arr[j + 1]
				if (!this.Protocol4(arr.get(j), arr.get(j + 1)))
				{
					// swap temp and arr[i]
					temp = arr.get(j);
					arr.set(j, arr.get(j + 1));
					arr.set(j + 1, temp);
				}
			}
		}

		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++)
		{
			min.add(arr.get(arr.size() - 1 - i));
		}

		if(e_sk != null)
		{
			System.out.println("ElGamal sorting");
			for(int i = 0; i < arr.size(); i++)
			{
				System.out.print(ElGamalCipher.decrypt(e_sk, arr.get(i)) + ", ");
			}
			System.out.println("");
			for(int i = 0; i < k; i++)
			{
				System.out.print(ElGamalCipher.decrypt(e_sk, min.get(i)) + ", ");
			}
			System.out.println("");
		}

		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return min;
	}

}
