package net.alext.sign;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * Chapter 6 Utils
 */
public class Utils6 extends Utils4
{
    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
	{
        KeyPairGenerator  kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    
        kpGen.initialize(1024, new SecureRandom());
    
        return kpGen.generateKeyPair();
	}
}