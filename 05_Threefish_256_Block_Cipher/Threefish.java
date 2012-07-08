import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.spec.IvParameterSpec;

/* CipherSpi abstract class: http://java.sun.com/javase/6/docs/api/javax/crypto/CipherSpi.html
 * Threefish-256 in CTR mode
 * Find spec inside here: http://www.skein-hash.info/sites/default/files/skein1.2.pdf
 * CTR mode with this cipher works like so:
 * K_i = K for all i blocks (the key is fixed)
 * T_i = T = IV for all i blocks (the iv is fixed)
 * M_i = i for all i blocks (the message is the counter, starting from zero)
 */

public class Threefish extends CipherSpi {

	// DO NOT STORE THE MESSAGE ANYWHERE, PROCESS IT ON THE FLY
	// TODO: you need these three methods at a minimum to pass	
	
	// global variables	
	int flag;
	long CTR;
	long[] M, K, T, keySchedule;	
	
	
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
		// TODO: some stuff here

		int blockSize = 0;
		// key stream
		byte[] S = new byte[32];		
		// cipher text
		byte[] cipher = new byte[inputLen];
		
		int len = 0;
		while (len < inputLen) {
		
			// when some part of the key stream is remaining
			if (flag > 0) {
				blockSize = 32 - flag;
				for (int i = 0; i < blockSize & i < inputLen; i++)
					cipher[i + len] = (byte) ((S[i + flag] ^ input[i + len]) & 0xFF);						
				// still some input left
				if ((inputLen - blockSize) > 0)
					flag = -1;
				// no input left
				else
					flag += inputLen;				
			}
			else{		
				
				// generate the key stream using the counter
				generateKeystream();
									
				// long to byte
				for(int m = 0; m < 4; m++){				
					for (int i = 0; i < 8; i++)
						S[i + m * 8] = (byte) (M[m] >>> (i * 8));				
				}
					
				// still input left
				if ( (inputLen - len) > 32) {
					blockSize = 32;
					flag = -1;
				}
				// last block
				else {
					blockSize = inputLen - len;
					flag = blockSize;
				}
				
				// xoring the key stream with the input text
				for ( int i = 0; i < blockSize; i++) {
					cipher[i + len] = (byte) ((S[i] ^ input[i + len]) & 0xFF);	
				}				
				
				// increasing counter
				CTR++;							
			}
			len += blockSize;	
		}
		return cipher;
	}

	
	// a function to generate the sub keys
	private void generateKeySchedule(int rnd) {
		
		keySchedule = new long[4];
				
		for (int i = 0; i < 4; i++) {
			keySchedule[i] = K[ (rnd + i) % 5 ];	
		}
		
		keySchedule[1] += T[ rnd % 3 ];
		keySchedule[2] += T[ (rnd + 1) % 3 ];
		keySchedule[3] += rnd;	
		
	}	
	
	
	// a function to generate the key stream from the counter
	private void generateKeystream() {
		
		long[] C = new long[4];
		
		// word permutation
		int[] P = { 0, 3, 2, 1};
	
		// rotation constants
		int[][] R =   { { 14, 16 }, 
						{ 52, 57 }, 
						{ 23, 40 }, 
						{ 5, 37 }, 
						{ 25, 33 },
						{ 46, 12 }, 
						{ 58, 22 }, 
						{ 32, 32 } };
				
		M = new long[4];
		M[0] = CTR;
		
		for (int i = 0; i < 72; i++) {			
			
			if(i % 4 == 0){				
				generateKeySchedule( i / 4 );
				for ( int m = 0; m < 4; m++){
					M[m] += keySchedule[m];
				}						
			}			
			
			//MIX
			int r = R[i % 8][0];
			C[0] = M[0] + M[1];
			C[1] = (M[1] << r) | (M[1] >>> (64 - r));
			C[1] ^= C[0];
				
			//MIX
			r = R[i % 8][1];											
			C[2] = M[2] + M[3];
			C[3] = (M[3] << r) | (M[3] >>> (64 - r));
			C[3] ^= C[2];
				
			//permute
			for ( int m = 0; m < 4; m++){
				M[m] = C[ P[m] ];
			}				
		}
		
		generateKeySchedule( 72 / 4 );		
		for ( int m = 0; m < 4; m++){
			M[m] += keySchedule[m];
		}	
	}
		
	
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		// TODO: some stuff here
		return engineDoFinal(input, inputOffset, inputLen);
	}

	
	protected void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random) {
		// TODO: some stuff here
		
		// initializing the counter value
		CTR = 0;
		// initializing the flag value
		flag = -1;
		
		// getting the key in right format
		byte[] keyByte = key.getEncoded();		
		K = new long[5];				
		for (int i = 0; i < 4; i++) {			
			K[i] =    ((long) (keyByte[7 + 8 * i] & 0xFF) << (8*7)) | ((long) (keyByte[6 + 8 * i] & 0xFF) << (8*6))
					| ((long) (keyByte[5 + 8 * i] & 0xFF) << (8*5)) | ((long) (keyByte[4 + 8 * i] & 0xFF) << (8*4))
					| ((long) (keyByte[3 + 8 * i] & 0xFF) << (8*3)) | ((long) (keyByte[2 + 8 * i] & 0xFF) << (8*2))
					| ((long) (keyByte[1 + 8 * i] & 0xFF) << (8*1)) | ((long) (keyByte[0 + 8 * i] & 0xFF) << (8*0));
		}
		
		// extending the key
		//2^64 = 18,446,744,073,709,551,616
		//2^64 /3 = 6,148,914,691,236,517,205
		K[4] = 6148914691236517205L;
		for (int i = 0; i < 4; i++){
			K[4] ^= K[i];
		}

		// getting the tweak in right format
		byte[] IV = ((IvParameterSpec) params).getIV();
		T = new long[3];
		for (int i = 0; i < 2; i++) {			
			T[i] = 	  ((long) (IV[7 + 8 * i] & 0xFF) << (8*7)) | ((long) (IV[6 + 8 * i] & 0xFF) << (8*6))
					| ((long) (IV[5 + 8 * i] & 0xFF) << (8*5)) | ((long) (IV[4 + 8 * i] & 0xFF) << (8*4))
					| ((long) (IV[3 + 8 * i] & 0xFF) << (8*3)) | ((long) (IV[2 + 8 * i] & 0xFF) << (8*2))
					| ((long) (IV[1 + 8 * i] & 0xFF) << (8*1)) | ((long) (IV[0 + 8 * i] & 0xFF) << (8*0));
		}
		// extending the tweak
		T[2] = T[0] ^ T[1];		
	}

	
	// TODO: implement anything below as needed
	
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
		return 0;
	}

	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
		return 0;
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
