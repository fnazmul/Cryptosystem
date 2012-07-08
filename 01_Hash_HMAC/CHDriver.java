import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.util.Arrays;

class CHDriver {

	public static void main(String args[]) {

		// add the custom provider
		Security.addProvider(new CryptosystemsProvider());

		MessageDigest algorithm = null;

		try {
			algorithm = MessageDigest.getInstance("CH");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid algorithm - HASH");
			System.exit(-1);
		}

		// the message
		byte[] m = { (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c, (byte)0x6f };

		// the hash
		byte[] h = algorithm.digest(m);

		// what the hash should be
		byte[] hcheck = {(byte)0x7c, (byte)0xe3, (byte)0x9, (byte)0xa2, (byte)0x5e, (byte)0x2e, (byte)0x16, (byte)0x3, (byte)0xca, (byte)0xf, (byte)0xc3, (byte)0x69, (byte)0x26, (byte)0x7b, (byte)0x4d, (byte)0x43, (byte)0xf0, (byte)0xb1, (byte)0xb7, (byte)0x44, (byte)0xac, (byte)0x45, (byte)0xd6, (byte)0x21, (byte)0x3c, (byte)0xa0, (byte)0x8e, (byte)0x75, (byte)0x67, (byte)0x56, (byte)0x64, (byte)0x44, (byte)0x8e, (byte)0x2f, (byte)0x62, (byte)0xfd, (byte)0xbf, (byte)0x7b, (byte)0xbd, (byte)0x63, (byte)0x7c, (byte)0xe4, (byte)0xf, (byte)0xc2, (byte)0x93, (byte)0x28, (byte)0x6d, (byte)0x75, (byte)0xb9, (byte)0xd0, (byte)0x9e, (byte)0x8d, (byte)0xda, (byte)0x31, (byte)0xbd, (byte)0x2, (byte)0x91, (byte)0x13, (byte)0xe0, (byte)0x2e, (byte)0xcc, (byte)0xcf, (byte)0xd3, (byte)0x9b};

		// check
		System.out.println(Arrays.equals(h, hcheck) ? "PASS" : "FAIL");

		// now the HMAC part
		Mac mac = null;
		
		// key is previous hash
		String mode = "HmacCH";
		SecretKey key = new SecretKeySpec(h, mode);

		try {
			mac = Mac.getInstance(mode);
			// initialize mac with key
			mac.init(key);
		} catch (Exception e) {
			System.err.println("Invalid algorithm - HMAC");
			System.exit(-1);
		}

		// message for mac
		byte[] m2 = {(byte)0x57, (byte)0x6F, (byte)0x72, (byte)0x6C, (byte)0x64};

		// produce the mac
		byte[] res = mac.doFinal(m2);

		// what the hmac should be
		byte[] mcheck = { (byte)0x90, (byte)0x0d, (byte)0x31, (byte)0x86, (byte)0x54, (byte)0xc5, (byte)0x3c, (byte)0xee, (byte)0x2a, (byte)0x4a, (byte)0x7e, (byte)0xe0, (byte)0x28, (byte)0xad, (byte)0x2a, (byte)0x81, (byte)0x90, (byte)0x92, (byte)0xcb, (byte)0xa0, (byte)0x51, (byte)0xe4, (byte)0x78, (byte)0xb5, (byte)0x3f, (byte)0x6a, (byte)0x3f, (byte)0x7f, (byte)0x05, (byte)0xf5, (byte)0x8b, (byte)0x33, (byte)0xcf, (byte)0xe6, (byte)0xb5, (byte)0x13, (byte)0x6e, (byte)0xc1, (byte)0xac, (byte)0xee, (byte)0xa0, (byte)0x83, (byte)0xeb, (byte)0x5d, (byte)0x4d, (byte)0xf8, (byte)0x14, (byte)0xb3, (byte)0x27, (byte)0xd8, (byte)0x9d, (byte)0x4b, (byte)0xd3, (byte)0x16, (byte)0x00, (byte)0xd0, (byte)0x5c, (byte)0x7c, (byte)0xd0, (byte)0x67, (byte)0xc9, (byte)0xcd, (byte)0x11, (byte)0xbb};

		// check
		System.out.println(Arrays.equals(res, mcheck) ? "PASS" : "FAIL");

	}
}

