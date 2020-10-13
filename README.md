# Homomorphic_Encryption
Homomorphic Encryption is a Java library that implements the following partially homomorphic encryption systems:
* Paillier  
* El-Gamal (Additive or multiplicative)  
* Goldwasser-Micali  
* DGK  

As the partially homomorphic encryption systems only support addition with two ciphertexts, other protocols been appended to extend its functionality, in particular:
* Secure Multiplication
* Secure Division
* Secure Comparison

As this library uses Java 8, the JAR file can be imported in an Android project as well.  
To edit the code, import the Java_PHE folder as an Eclipse Project.

## Installation

Run the included installation script if on a Linux environment to install Java.

```bash
./install.sh

```

Note: If you want to use this module for a library, please use the release JAR or create a new one from the master branch. The development branch does share the private key to verify functionality of protocols.

## Usage
Import the packages as necessary. See Main.java 

```java
// Using Paillier

// 1- KeyPair generation
PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
p.initialize(KEY_SIZE, null);
KeyPair pe = p.generateKeyPair();
pk = (PaillierPublicKey) pe.getPublic();
sk = (PaillierPrivateKey) pe.getPrivate();
				
// 2- Encrypt and decrypt
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.decrypt(c, pk);
// c = 10

// 3- Scalar multiplication and addition
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.add(c, c, pk); 
// 10 + 10 = 20. Notice both arguments need to be encrypted

c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.multiply(c, BigInteger.TEN, pk);
// c = 10 * 10 = 100. 
// First argument is cipher-text, second is plain-text value

// Using El-Gamal - Multiplicative

// Using DGK

// Using Goldwasser-Micali

// Feature: Secure Multiplication

// Feature: Secure Division

// Feature: Secure Comparison

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors and acknowledgment
Java author: Andrew Quijano  
C++ author: David Lalo

All papers and protocols used in the code have been published in various cryptography journals. Please view the Papers directory to read the paper our code implements. 

The work to create this repository was funded by the US NSF REU Site at FIU under the grant number REU CNS-1461119.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Project status
The project is currently fully tested. To see an example how to use it, unzip the example.zip file and play the video. Currently the primary thing misssing is being able to create certificates for these homomorphic encryption schemes.