import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PublicKey;
import java.security.SecureRandom;

public class GFKeyPairGenerator extends KeyPairGeneratorSpi {

	private SecureRandom rnd = null;
	
	public KeyPair generateKeyPair() {
		// TODO: work only in this method
		BigInteger k = new BigInteger(1279, rnd);
		
		GFElement alpha = new GFElement("2", 16);
		GFElement alphaK = alpha.pow(k);
		
		return new KeyPair(new GFPublicKey(alphaK), new GFPrivateKey(k));		
	}

	public void initialize(int keysize, SecureRandom random) {
		rnd = random;
	}

}
