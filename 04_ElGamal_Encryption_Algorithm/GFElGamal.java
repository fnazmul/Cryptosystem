import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.ShortBufferException;

public class GFElGamal extends CipherSpi {
	
	int opMode;
	Key newKey;
	SecureRandom ranDom;	
		
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
		// TODO: most of your work goes here
		
		// ENCRYPT_MODE
		if (opMode == 1) {						
			// padding message
			byte[] P1 = new byte[160];
			byte[] P2 = new byte[160];			
						
			for (int i = 0; i < input.length; i++) {
				P1[i] = input[i];			
			}						
			for (int i = input.length; i < 159; i++) {
				P1[i] = (byte) (159 - input.length);				
			}			
			P1[159] = 0;			
			for (int i = 0; i < 160; i++) {
				P2[i] = P1[159 - i];				
			}			
			GFElement pText = new GFElement(P2);			
			
			// generating alpha, gamma, delta 
			BigInteger k = new BigInteger(1279, ranDom);			
		
			GFPublicKey key = (GFPublicKey) newKey;
			GFElement publicKey = key.getValue().pow(k);
			GFElement delta = pText.multiply(publicKey);
			
			GFElement alpha = new GFElement("2", 16);
			GFElement gamma = alpha.pow(k);
						
			byte[] gammaByte = gamma.current.toByteArray();			
			byte[] deltaByte = delta.current.toByteArray();
			
			// combining gamma and delta
			byte[] result = new byte[320];			                         			                         
			for (int i = 0; i < 160; i++) {
				result[i] = gammaByte[i];
			}
			for (int i = 160; i < 320; i++){
				result[i] = deltaByte[i - 160];
			}
			
			return result;
		}
		// DECRYPT_MODE
		else {
			
			// extracting gamma
			byte[] gammaByte = new byte[160];
			for (int i = 0; i < 160; i++) {
				gammaByte[i] = input[i];
			}
			
			// extracting delta
			byte[] deltaByte = new byte[160];
			for (int i = 0; i < 160; i++){
				deltaByte[i] = input[160 + i];
			}
			
			//	extracting plain text
			GFPrivateKey privateKey = (GFPrivateKey) newKey;
			
			GFElement gamma = new GFElement(gammaByte);
			gamma = gamma.pow(privateKey.getValue());
			gamma = gamma.inverse();
			
			GFElement delta = new GFElement(deltaByte);
			delta = gamma.multiply(delta);
			
			byte[] pText = delta.current.toByteArray();
			
			int length = (159 - pText[1]) & 255;
			byte[] result = new byte[length];
			for (int i = 0; i < length; i++) {
				result[i] = pText[159 - i];
			}
			
			return result;
			
		}
	}

	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
		return 0;
	}

	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
		return 0;
	}

	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		return null;
	}

	protected void engineInit(int opmode, Key key, SecureRandom random) {
		// TODO: some work here too
		opMode = opmode;
		newKey = key;
		ranDom = random;
	}

	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {

	}

	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {

	}

	// nothing really interesting below here

	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	protected byte[] engineGetIV() {
		return null;
	}

	protected int engineGetOutputSize(int inputLen) {
		return 0;
	}

	protected int engineGetBlockSize() {
		return 0;
	}

	protected void engineSetPadding(String padding) {

	}

	protected void engineSetMode(String mode) {
		
	}
}
