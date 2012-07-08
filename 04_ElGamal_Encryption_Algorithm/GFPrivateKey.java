import java.math.BigInteger;
import java.security.PrivateKey;

// no need to touch
public class GFPrivateKey implements PrivateKey {

	private final BigInteger k;
	
	GFPrivateKey(BigInteger k) {
		this.k = k;
	}
	
	public BigInteger getValue() {
		return k;
	}
	
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

}
