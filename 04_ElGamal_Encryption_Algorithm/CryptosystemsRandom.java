import java.security.SecureRandomSpi;
import java.util.Random;

// don't touch this class
public class CryptosystemsRandom extends SecureRandomSpi {

	// lfsr: x^32 + x^30 + x^26 + x^25 + 1
	int s = 0xFEEDFACE;
	
	@Override
	protected byte[] engineGenerateSeed(int numBytes) {
		byte[] b = new byte[numBytes];
		for(int i=0; i<b.length; i++) b[i] = clock();
		return b;
	}

	@Override
	protected void engineNextBytes(byte[] bytes) {
		for(int i=0; i<bytes.length; i++) bytes[i] = clock();
	}

	@Override
	protected void engineSetSeed(byte[] seed) {
	}

	private byte clock() {
		byte b = (byte)s;
		s = (s >>> 8 | (s ^ (s >>> 7) ^ (s >>> 6) ^ (s >>> 2)) << 24);
		return b;
	}
	
}
