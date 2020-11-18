#!/bin/bash

# Only run from the src directory!
javac -cp "." -Xlint -sourcepath "." Main.java 

# Run the program
java -cp "." Main $1
