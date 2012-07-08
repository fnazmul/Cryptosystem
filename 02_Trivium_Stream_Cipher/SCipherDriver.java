import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

class SCipherDriver {

	public static void main(String args[]) {
		// add our custom provider
		Security.addProvider(new CryptosystemsProvider());

		// key and iv
		byte[] k = {(byte)0x0F,(byte)0x62,(byte)0xB5,(byte)0x08,(byte)0x5B,(byte)0xAE,(byte)0x01,(byte)0x54,(byte)0xA7,(byte)0xFA};
		byte[] iv = {(byte)0x28,(byte)0x8F,(byte)0xF6,(byte)0x5D,(byte)0xC4,(byte)0x2B,(byte)0x92,(byte)0xF9,(byte)0x60,(byte)0xC7};

		// setup cipher using key and iv
		String mode = "SCipher";
		Cipher c = null;
		try {
			c = Cipher.getInstance(mode);
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, mode), new IvParameterSpec(iv));
		} catch(Exception e) { System.out.println("Exception."); }

		// first test
		byte[] b1 = new byte[16];
		byte[] ks = c.update(b1);
		byte[] check1 = {(byte)0xa4,(byte)0x38,(byte)0x6c,(byte)0x6d,(byte)0x76,(byte)0x24,(byte)0x98,(byte)0x3f,(byte)0xea,(byte)0x8d,(byte)0xbe,(byte)0x73,(byte)0x14,(byte)0xe5,(byte)0xfe,(byte)0x1f};
		if(Arrays.equals(check1,ks)) System.out.println("PASS");
		else System.out.println("FAIL");

		// reset cipher
		try {
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, mode), new IvParameterSpec(iv));
		} catch(Exception e) { System.out.println("Exception."); }

		// second test
		byte[] b2 = {(byte)0x48,(byte)0x65,(byte)0x6C,(byte)0x6C,(byte)0x6F};
		byte[] check2 = {(byte)0xEC, (byte)0x5D, (byte)0x00, (byte)0x01, (byte)0x19};
		byte[] ct = c.update(b2);
		if(Arrays.equals(check2,ct)) System.out.println("PASS");
		else System.out.println("FAIL");

	}
}

