import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

public class ThreefishDriver {

	private static int s = 0xFEEDFACE;
	
	public static void rnd(byte[] b) {
		for(int i=0; i<b.length; i++) {
			b[i] = (byte)(s & 0xFF);
			s = (s >>> 8 | (s ^ (s >>> 7) ^ (s >>> 6) ^ (s >>> 2)) << 24);
		}
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		String check1 = "9daf033bad008f360c517f5cc7ac2b0a8170f1ac6754b68effaaab8f04aee694082cddf564c5222957ef6671560db965f90f01d43aaad6a4979690bf0e8f647e1e8e8842c6572567fd3b2e5529cfed5bd348f85b256d5351d0b27b9c41059e8e2e3bfcd932513e62f4f546b75148da58a593fced138b111611bd0acdf8d96d";
		String check2 = "7634165a82524bb9abc247d273940f50b03da94e47303a31ec304539dd1a88c896c81eebbbd7be98fb2cababd67c14d30d8e84ef918ca4bde5c5d27cbee1aecf49f684de40d13e5b54813b3fe6db82073f794a64b6693a4d03018d89512a46bebe019320ee7eae5af0970771945a22321d99174781e0f62d6c65d287dd1acb";
		
		// add our custom provider
		Security.addProvider(new CryptosystemsProvider());

		// a message, key, tweak, and temporary buffer
		byte[] p = new byte[127]; rnd(p);
		byte[] k = new byte[ 32]; rnd(k);
		byte[] t = new byte[ 16]; rnd(t);
		byte[] b = new byte[127];
		
		// setup cipher using key and iv
		String mode = "Threefish";
		Cipher c = null;

		// test 1 : encryption
		try {
			c = Cipher.getInstance(mode);
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, mode), new IvParameterSpec(t));
			b = c.doFinal(p);
		} catch(Exception e) { e.printStackTrace(); }
		if(check1.equals(byteArrayToHexString(b))) System.out.println("PASS");
		else System.out.println("FAIL");

		// test 2 : decryption
		// reset cipher
		try {
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, mode), new IvParameterSpec(t));
			b = c.doFinal(b);
		} catch(Exception e) { e.printStackTrace(); }
		if(Arrays.equals(p,b)) System.out.println("PASS");
		else System.out.println("FAIL");

		// test 3 : really long encryption
		// NOTE: this test is to make sure your implementation makes sense
		// i.e. you should not be storing the message bytes, but processing them on the fly
		try {
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, mode), new IvParameterSpec(t));
			for(int i=0; i< 1 << 20; i++) {
				rnd(b);
				c.update(b);
			}
			rnd(b);
			b = c.doFinal(b);
		} catch(Exception e) { e.printStackTrace(); }
		if(check2.equals(byteArrayToHexString(b))) System.out.println("PASS");
		else System.out.println("FAIL");

	}
	
	public static String byteArrayToHexString(byte[] b) {
		StringBuffer sb = new StringBuffer(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			int v = b[i] & 0xff;
			if (v < 16) sb.append('0');
			sb.append(Integer.toHexString(v));
		}
		return sb.toString();
	}

}
