This is a module created from the SST REU 2017 project.
This is a module for easy implementation of the following partially Homomorphic systems:
- ElGamal
- Paillier
- DGK
- Goldwasser-Micali

----Requirements-----
JRE 1.8
As this uses Java 8, this code can be imported/used by Android Phones as well!

-------Papers------------
Check the Papers folder for research papers from which this library implemented the repository.
Functionalities will have the functions and corresponding paper.

-------How to export to JAR file to use in other projects------

1- Download the repository and load it as an Eclipse Project
2- Right-Click Project and select Export
3- Select Java/Java JAR file
4- Be sure you selected the right project! 
5- Be sure to NOT select the default package as that only contains test cases as an example for you to use!
6- Be sure to select to export only generated class files/resources. The source code is here in this repository anyways!
7- Select the path of where JAR file will be exported.
8- View https://github.com/AndrewQuijano/SSTREU2017 repository, which shows it uses the jar file from this repository.

----------FUNCTIONALITIES----------------

Operations supported for all partially homomorphic systems:
1- Addition
2- Subtraction
3- Multiplication (See alice/bob and Mau paper)
4- Division (See Divison.pdf paper) ****THERE IS A FAST AND LESS ACCURATE AND A SLOW BUT ACCURATE DIVISION **** SEE PAPER/CODE CAREFULLY!
5- Signature (DGK isn't exactly verified but technically works)
6- Comparison Protocols (See Comparison.pdf, there is a typo and it is verified by Veugen, see below)
For comparison protocols, the code follows the same logic that Bob has the private key and Alice doesn't.
Please note: The comparison protocols work regardless of whether it is Paillier, DGK or ElGamal, just minor modifications are needed.
Note we denote [[x]] and [[y]] as encrypted x and y respectively.
Also: 1 now corresponds to true and 0 corresponds to false

A- Protocol 1: Compare private x and y and if(x < y) return 1 else return 0
B- Protocol 2: Compare [[x]] and [[y]] and if (x >= y) return 1 else return 0 NOTE: DGK is if(x > y) return 1 else return 0
A- Protocol 3: Compare private x and y and if(x < y) return 1 else return 0
B- Protocol 4: Compare [[x]] and [[y]] and if (x >= y) return 1 else return 0

Customizations:
1- By default Alice will use MergeSort to sort encrypted arrays. QuickSort is about the same speed.
2- How to use each Protocol...If Alice wants to use a method, Bob must call the correct method for this to work correctly...

Please see the Main.java to see how to use the library for your own project.
Alternatively you can check the following project:
https://github.com/AndrewQuijano/SSTREU2017

-----------Precautions---------------
If your code is using the driver and is froezen when using methods from this library on run-time, 
you probably have a mis-match in functions being used.
For example, Alice is using Protocol 2 and Bob is using Protocol 4.
If you catch an Optional Data Exception, this is also symptom that alice/bob have a mismatched method e. g. alice trying to use Protocol 4 and bob trying to use multiplication.

NOTE: If you want to use this code for an application PLEASE USE MASTER Branch.
The video has used code on development branch to demonstrated it worked!
The Master branch DOES NOT have the code of Alice receiving the private key for debugging/verification.

---------------------How to use Test Driver and follow example on PPT------------------------------------
As seen from the video, the Windows 10 was the Host OS and assumed the role of Bob.
Bob was executed on Windows 10 Eclipse environment where no arguments were given.

The Ubuntu VM was alice as I placed a command line argument.
As of 2/17/2020 11:31 PM EST, this should work perfectly. 

----------TO DO----------------------
1- Currently I hope to use the Bouncy castle API to generate certificates from these.
3- Start C++ creation, but NTL installation needs to be completing
