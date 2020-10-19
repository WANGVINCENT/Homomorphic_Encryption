

# Homomorphic Encryption
Homomorphic Encryption is a Java library that implements the following partially homomorphic encryption systems:
* Paillier  
* El-Gamal (Additive or multiplicative)  
* Goldwasser-Micali  
* DGK  

As the partially homomorphic encryption systems only support addition with two ciphertexts, other protocols been appended to extend its functionality, in particular:
* Secure Multiplication
* Secure Division
* Secure Comparison

## Installation
Please retreieve the JAR file from the latest release:
https://github.com/AndrewQuijano/Homomorphic_Encryption/tags

As this library uses Java 8, the JAR file can be imported into an Android project.
If you want to review/edit the library, import the JAVA_PHE directory into a Eclipse project and edit as necessary. The Main.java folder only exists for testing and provide examples of how to use the library.

## Usage
Import the packages as necessary. See Main.java 

# security.DGK
# security.elgamal
# security.gm
# [security.paillier] (https://github.com/AndrewQuijano/Homomorphic_Encryption/blob/master/Java_PHE/src/security/paillier/)

**Generate Paillier Keys**
```java
int KEY_SIZE = 1024; //number of bits
SecureRandom r = new SecureRandom();
PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
p.initialize(KEY_SIZE, r);
KeyPair pe = p.generateKeyPair();
pk = (PaillierPublicKey) pe.getPublic();
sk = (PaillierPrivateKey) pe.getPrivate();
```

**encrypt(plaintext, pk)**
Encrypt a plain-text BigInteger using the Paillier Cryptography system.
* Parameters
    * plaintext (**BigInteger**)
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**)    
* Raises (**IllegalArgumentException**)
    * If the plaintext is negative or exceeds plaintext space that can be handled by the Paillier Public Key, this exception will be generated.

**decrypt(ciphertext, sk)**
Decrypt a cipher-text BigInteger using the Paillier Cryptography system.
* Parameters
    * ciphertext (**BigInteger**)
    * sk (**PaillierPrivateKey**)
* Returns
    * plaintext (**BigInteger**)    
* Raises (**IllegalArgumentException**)
    * If the ciphertext is negative or exceeds ciphertext space that can be handled by the Paillier Private Key, this exception will be generated.
```java
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.decrypt(c, pk); // c = 10
```

**add(ciphertext1, ciphertext2, pk)**
Add the results of both ciphertexts.
* Parameters
    * ciphertext1 (**BigInteger**) - a Paillier ciphertext
    * ciphertext2 (**BigInteger**) - a second Paillier ciphertext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both ciphertexts    
* Raises (**IllegalArgumentException**)
    * N/A

**add_plaintext(ciphertext, plaintext, pk)**
Add the value in plaintext within the ciphertext. This is much faster than regular add as you save an encryption operation.
* Parameters
    * ciphertext (**BigInteger**) - a Paillier ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**IllegalArgumentException**)
    * N/A
```java
// Addition
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.add(c, c, pk); 
// c = 10 + 10 = 20. Notice both arguments need to be encrypted. c is still encrypted!
// Scalar addition
BigInteger d = PaillierCipher.encrypt(BigInteger.TEN, pk);
d = PaillierCipher.add_plaintext(d, BigInteger.TEN, pk);
// d = 10 + 10 = 20. The second argument must be a plaintext if using plaintext addition! d is still encrypted!
```

```java
c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.multiply(c, BigInteger.TEN, pk);
// c = 10 * 10 = 100. 
// First argument is cipher-text, second is plain-text value
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors and acknowledgment
Java author: Andrew Quijano  
C++ author: David Lalo

All papers and protocols used in the code have been published in various cryptography journals. Please view the Papers directory to read the paper our code implements. If you use this library, please cite the

The work to create this repository was funded by the US NSF REU Site at FIU under the grant number REU CNS-1461119.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Project status
The project is currently fully tested. To see an example how to use it, unzip the example.zip file and play the video. Currently, the strech goal is to implement certificates using the Bouncy Castle API for these homomorphic encryption systems.