
import javax.crypto.*;

import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.IvParameterSpec;

import java.util.BitSet;

// CipherSpi abstract class:
//http://java.sun.com/javase/6/docs/api/javax/crypto/CipherSpi.html

public class SCipher extends CipherSpi {

       // defining global variables 
	   // state s is divided into 3 BitSets
		BitSet s1 = new BitSet(93);		// state bits s_1, .., s_93
		BitSet s2 = new BitSet(84);		// state bits s_94, .., s_177
		BitSet s3 = new BitSet(111);	// state bits s_178, .., s_288
		
		// variables for the key and the IV
		byte[] keyByte;
        byte[] IVByte;
 
       
       protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                       byte[] output, int outputOffset) throws ShortBufferException {

               return 0;
       }

       protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {

               return null;
       }

       protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                       byte[] output, int outputOffset) throws ShortBufferException {

               return 0;
       }

       protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

    	   	   // copying the plain text from the input
    	   	   byte[] plainText = new byte[inputLen];
               for (int i = 0; i < inputLen; i++) {
                       plainText[i] = input[inputOffset + i];
               }
    	   
               // initializing output key stream bits, length of the key stream is the same as the input
               BitSet ksBits = new BitSet(inputLen * 8);

               // generating the key stream bits
               boolean t1, t2, t3;
               for (int i = 0; i < inputLen * 8; i++) {

            	   	   // t_1 <- s_66 ^ s_93
                       t1 = s1.get(65) ^ s1.get(92) ;
                       
                       // t_2 <- s_162 ^ s_177
                       t2 = s2.get(68) ^ s2.get(83) ;
                       
                       // t_3 <- s_243 ^ s_288
                       t3 = s3.get(65) ^ s3.get(110);
                       

                       // ith bit of output key stream
                       ksBits.set(i, t1 ^ t2 ^ t3);
                       
                       
                       // t_1 <- t_1 ^ s_91 ^ s_92 ^ s_171
                       t1 ^= (s1.get(90)  & s1.get(91))  ^ s2.get(77);
                       
                       // t_2 <- t_2 ^ s_175 ^ s_176 ^ s_264
                       t2 ^= (s2.get(81)  & s2.get(82))  ^ s3.get(86);
                       
                       // t_3 <- t_3 ^ s_286 ^ s_287 ^ s_69
                       t3 ^= (s3.get(108) & s3.get(109)) ^ s1.get(68);
                       
                       
                       // shifting and updating state bits
                       for (int j = 92; j > 0; j--)
                               s1.set(j, s1.get(j - 1));
                       s1.set(0, t3);
                       
                       for (int j = 83; j > 0; j--)
                               s2.set(j, s2.get(j - 1));
                       s2.set(0, t1);
                       
                       for (int j = 110; j > 0; j--)
                               s3.set(j, s3.get(j - 1));
                       s3.set(0, t2);
               }               
               
               // the key stream output
               byte[] ksOut = new byte[inputLen];
               
               // converting the output key stream into a byte array
               byte[] ksBytes = toByteArray(ksBits,inputLen);          
               
               // XORing the key stream with plain text
               for (int i = 0; i < inputLen; i++) {
                       ksOut[i] = (byte) (plainText[i] ^ ksBytes[i]);
               }

               return ksOut;
       }
       

       protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
                             
               // getting the Key and the IV as byte arrays
               keyByte = key.getEncoded();
               IVByte  = ((IvParameterSpec) params).getIV();

               // converting the Key and the IV into BitStream
               BitSet keyBit = fromByteArray(keyByte);
               BitSet IVBit  = fromByteArray(IVByte);
               
               // initializing all state bits to zero
               s1.clear();		// state bits s_1, .., s_93
               s2.clear();		// state bits s_94, .., s_177
               s3.clear();	// state bits s_178, .., s_288
                               
               // initializing s1 i.e. state bits s_1, .., s_93 with the key
               //(s_1,s_2,...,s_93) <- (K_80,...,K_1,0,...,0)
               for (int i = 0; i < 80; i++)
                       s1.set(i, keyBit.get(79 - i));

               // initializing s2 i.e. state bits s_94, .., s_177 with the IV
               //(s_94,s_95,...,s_177) <- (IV_80,...,IV_1,0,...,0)
               for (int i = 0; i < 80; i++)
                       s2.set(i, IVBit.get(79 - i));

               // initializing s3 i.e. setting s_285,s_286,s_287 to 1
               //(s_178,s_179,...,s_288) <- (0,...,0,1,1,1)
               s3.set(108, 111);

                                             
               // 4 full cycles to initialize the states...i.e. 4*288 iterations
               boolean t1, t2, t3;
               for (int i = 0; i < 1152; i++) {

            	   	   // t_1 <- s_66 ^ s_93 ^ s_92 ^ s_91 ^ s_171
                       t1 = s1.get(65) ^ s1.get(92)  ^ (s1.get(91)  & s1.get(90))  ^ s2.get(77);
                       
                       // t_2 <- s_162 ^ s_177 ^ s_176 ^ s_175 ^ s_264
                       t2 = s2.get(68) ^ s2.get(83)  ^ (s2.get(82)  & s2.get(81))  ^ s3.get(86);
                       
                       // t_3 <- s_243 ^ s_288 ^ s_287 ^ s_286 ^ s_69
                       t3 = s3.get(65) ^ s3.get(110) ^ (s3.get(109) & s3.get(108)) ^ s1.get(68);
                       
                       
                       // shifting and updating state values
                       for (int j = 92; j > 0; j--)
                               s1.set(j, s1.get(j - 1));
                       s1.set(0, t3);

                       for (int j = 83; j > 0; j--)
                               s2.set(j, s2.get(j - 1));
                       s2.set(0, t1);

                       for (int j = 110; j > 0; j--)
                               s3.set(j, s3.get(j - 1));
                       s3.set(0, t2);
               }

       }
       

       
     // function that returns a byte array from a bit set
     // bits are packed into a byte in reverse order
       public byte[] toByteArray(BitSet bits, int length) {
    	   
               byte[] byteArray = new byte[length];

               for (int i = 0; i < 8 * length; i++) {
                       if (bits.get(i)) {
                               byteArray[i / 8] |= 1 << (i % 8);
                       }
               }

               return byteArray;
       }

       
       //function that returns a bit set from a byte array
       //the byte-ordering of bytes are little-endian which means the LSB is in element 0
       public BitSet fromByteArray(byte[] bytes) {
               BitSet bits = new BitSet(8 * bytes.length);
               for (int i = 0; i < bytes.length * 8; i++) {
                       if ((bytes[i / 8] & (1 << (i % 8))) > 0) {
                               bits.set(i);
                       }
               }
               return bits;
       }

       
       protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {

       }

       protected void engineInit(int opmode, Key key, SecureRandom random) {

       }
       
       
       protected AlgorithmParameters engineGetParameters() {

               return null;
       }

       
       protected byte[] engineGetIV() {

               return null;
       }

       
       protected int engineGetOutputSize(int inputLen) {

               return inputLen;
       }

       
       protected int engineGetBlockSize() {

               return 0;
       }

       
       protected void engineSetPadding(String padding) {

       }

       
       protected void engineSetMode(String mode) {

       }

}