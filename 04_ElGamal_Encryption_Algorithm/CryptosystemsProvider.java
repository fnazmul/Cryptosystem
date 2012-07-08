import java.security.Provider;

// no need to touch
public class CryptosystemsProvider extends Provider {

	public CryptosystemsProvider() {
		super("CryptosystemsProvider", 1.0, "CryptosystemsProvider");
		put("KeyPairGenerator.GF", "GFKeyPairGenerator");
		put("Cipher.GFElGamal", "GFElGamal");
		put("SecureRandom.CryptosystemsRandom", "CryptosystemsRandom");
	}

}
