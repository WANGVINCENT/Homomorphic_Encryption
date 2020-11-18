package test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;

import security.DGK.DGKKeyPairGenerator;
import security.elgamal.ElGamalKeyPairGenerator;
import security.gm.GMCipher;
import security.gm.GMKeyPairGenerator;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.bob;

public class Server 
{
	// Initialize Alice and Bob
	private static ServerSocket bob_socket = null;
	private static Socket bob_client = null;
	private static bob andrew = null;
	
	private static final int KEY_SIZE = 1624;

	// Get your test data...
	private static BigInteger [] low = StressTest.generate_low();
	private static BigInteger [] mid = StressTest.generate_mid();
	
	public static void main(String [] args) throws HomomorphicException
	{
		try
		{
			// Build DGK Keys
			DGKKeyPairGenerator gen = new DGKKeyPairGenerator(16, 160, 1624);
			gen.initialize(KEY_SIZE, null);
			KeyPair DGK = gen.generateKeyPair();
			
			// Build Paillier Keys
			PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
			p.initialize(KEY_SIZE, null);
			KeyPair pe = p.generateKeyPair();
			
			// Build ElGamal Keys
			ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
			// NULL -> ADDITIVE
			// NOT NULL -> MULTIPLICATIVE
			pg.initialize(KEY_SIZE, new SecureRandom());
			KeyPair el_gamal = pg.generateKeyPair();
			
			// Build GM Keys
			GMKeyPairGenerator gmg = new GMKeyPairGenerator();
			gmg.initialize(KEY_SIZE, null);
			KeyPair gm = gmg.generateKeyPair();
			
			basic_Paillier(pe);
			basic_gm(gm);
			System.exit(0);
			
			bob_socket = new ServerSocket(9254);
			System.out.println("Bob is ready...");
			bob_client = bob_socket.accept();
			andrew = new bob(bob_client, pe, DGK, el_gamal);
			
			// Test K-Min using Protocol 4
			// Line 99 in Alice matches to Line 158-165 in Bob
			andrew.setDGKMode(false);
			andrew.run();// Sort Paillier
			andrew.setDGKMode(true);
			andrew.run();// Sort DGK
			if(andrew.getElGamalPublicKey().ADDITIVE)
			{
				andrew.repeat_ElGamal_Protocol4();
			}

			// Lines 162-163 in Alice matches to Line 167-168 in Bob
			bob_demo();
			bob_demo_ElGamal();

			// Stress Test the Protocols (get time to compute)
			//andrew.setDGKMode(false);
			//bob(); //Paillier
			//andrew.setDGKMode(true);
			//bob(); //DGK
			//bob_ElGamal();
		}
		catch (IOException | ClassNotFoundException x)
		{
			x.printStackTrace();
		}
		catch(IllegalArgumentException o)
		{
			o.printStackTrace();
		}
		finally
		{
			try 
			{
				if(bob_client != null)
				{
					bob_client.close();
				}
				if(bob_socket != null)
				{
					bob_socket.close();
				}
			}
			catch (IOException e) 
			{
				e.printStackTrace();
			}
		}
	}
	
	public static void basic_Paillier(KeyPair p) throws HomomorphicException
	{
		PaillierPublicKey pk = (PaillierPublicKey) p.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) p.getPrivate();
		
		// Test D(E(X)) = X
		BigInteger a = PaillierCipher.encrypt(BigInteger.TEN, pk);
		a = PaillierCipher.decrypt(a, sk);
		assert(BigInteger.TEN.equals(a));
		
		// Test Addition
		a = PaillierCipher.encrypt(a, pk);
		a = PaillierCipher.add(a, a, pk);//20
		assert(new BigInteger("20").equals(PaillierCipher.decrypt(a, sk)));
		
		// Test Subtraction
		a = PaillierCipher.subtract(a, PaillierCipher.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		assert(BigInteger.TEN.equals(PaillierCipher.decrypt(a, sk)));
		
		// Test Multiplication
		a = PaillierCipher.multiply(a, BigInteger.TEN, pk); // 10 * 10
		assert(new BigInteger("100").equals(PaillierCipher.decrypt(a, sk)));
		
		// Test Division
		a = PaillierCipher.divide(a, new BigInteger("2"), pk); // 100/2 
		assert(new BigInteger("50").equals(PaillierCipher.decrypt(a, sk)));
	}
	
	public static void basic_gm(KeyPair p) throws HomomorphicException 
	{
		GMPublicKey pk = (GMPublicKey) p.getPublic();
		GMPrivateKey sk = (GMPrivateKey) p.getPrivate();
		
		// Test D(E(X)) = X
		List<BigInteger> a = GMCipher.encrypt(BigInteger.TEN, pk);
		assert(BigInteger.TEN.equals(GMCipher.decrypt(a, sk)));
		
		// Test XOR
		BigInteger [] c = GMCipher.xor(a, a, pk);
		assert(BigInteger.ZERO.equals(GMCipher.decrypt(c, sk)));
	}
	
	// ------------------------------------ Basic demo methods-------------------------------------
	public static void bob_demo() throws ClassNotFoundException, IOException, HomomorphicException
	{
		// Test out-source multiplication, DGK
		andrew.setDGKMode(true);
		for(int i = 0; i < 3; i++)
		{
			andrew.multiplication();
		}
		andrew.setDGKMode(false);
		for(int i = 0; i < 3; i++)
		{
			andrew.multiplication();
		}
		System.out.println("Finished Testing Multiplication");
		
		// Test Protocol 3
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol3(mid[i % 16]);
		}
		for(int i = 0; i < 16 * 2; i++)
		{
			andrew.Protocol3(low[i % 16]);
		}
		System.out.println("Finished Testing Protocol 3");

		// Test Protocol 1
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol1(mid[i % 16]);
		}
		System.out.println("Finished Testing Protocol 1");

		// Test Modified Protocol 3
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Modified_Protocol3(mid[i % 16]);
		}
		System.out.println("Finished Testing Modified Protocol 3");
		
		// Test Protocol 2 with Paillier
		andrew.setDGKMode(false);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol2();
		}
		System.out.println("Finished Testing Protocol 2 w/ Paillier");
		
		// Test Protocol 2 with ElGamal
		System.out.println("Finished Testing Protocol 2 w/ ElGamal");
		
		
		// Test Protocol 4 with Paillier
		andrew.setDGKMode(false);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol4();
		}
		System.out.println("Finished Testing Protocol 4 w/ Paillier");
			
		// Test Protocol 4 with DGK
		andrew.setDGKMode(true);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol4();
		}
				
		System.out.println("Finished Testing Protocol 4 w/ DGK");
		// Division Protocol Test, Paillier
		andrew.setDGKMode(false);
		andrew.division(2);
		andrew.division(3);
		andrew.division(4);
		andrew.division(5);
		andrew.division(25);
		
		// Division Test, DGK
		andrew.setDGKMode(true);
		andrew.division(2);
		andrew.division(3);
		andrew.division(4);
		andrew.division(5);
		andrew.division(25);
	}
	
	//--------------------------Basic demo methods with ElGamal------------------------------------------	
	
	public static void bob_demo_ElGamal() throws ClassNotFoundException, IOException
	{
		if(!andrew.getElGamalPublicKey().ADDITIVE)
		{
			// Addition
			andrew.addition(true);
			andrew.addition(true);
			andrew.addition(true);
			// Subtract
			andrew.addition(false);
			andrew.addition(false);
			andrew.addition(false);
			return;
		}

		for(int i = 0; i < 3; i++)
		{
			andrew.ElGamal_multiplication();
		}

		// Division Test, ElGamal	
		andrew.ElGamal_division(2);
		andrew.ElGamal_division(3);
		andrew.ElGamal_division(4);
		andrew.ElGamal_division(5);
		andrew.ElGamal_division(25);

		// Test Protocol 4 with ElGamal
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.ElGamal_Protocol4();
		}
	}
}
