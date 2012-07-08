import java.security.Provider;

public class CryptosystemsProvider extends Provider {

	public CryptosystemsProvider() {
		super("CryptosystemsProvider", 1.0, "CryptosystemsProvider");
		put("MessageDigest.CH", "CHMessageDigest");
		put("Mac.HmacCH", "HmacCH");
	}

}
