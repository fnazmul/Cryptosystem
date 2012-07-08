import java.security.PublicKey;

// no need to touch
public class GFPublicKey implements PublicKey {

	private final GFElement a;
	
	GFPublicKey(GFElement a) {
		this.a = a;
	}
	
	public GFElement getValue() {
		return a;
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
