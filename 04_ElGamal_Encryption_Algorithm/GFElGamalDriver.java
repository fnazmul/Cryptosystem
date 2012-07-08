import javax.crypto.*;

import java.math.BigInteger;
import java.security.*;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

class GFElGamalDriver {

	public static void main(String args[]) {

		String check_t0 = "422b463d06b645dd7ac01a11c7746db41ff8b3ffe22a599ed0f690904461eae8c1cf019040e9963ceac235585664b7474aa2890c9c2804d824ea2e75b96540439702d5aba0e32c8a2167857a60f1b33cb140285d812218e8a041650d17220cf0ac75ae2d446c19a344a0388a8a65839355c09ef7f3e44062edaae4a4f344e89fdf5a72c7154fe65af5e374ca69d8b91e3b0c0249a892aa8c7f0026c35ca0347c";
		String check_pub = "2ce828d5b006fd0a967f3ce857a64d77999dce6ef9fe8fcdff3cbed7c4085571b9f89126e17d28c5773a29c0c934d20d7f52273a761e4f5f4e48131649d936c835e30461669c8ea222d7def6b9b8647d5d605b9eb23af40bba7f23ace7b6af6a114146baf280f57566e6308bf73856188bd01382129320ddef8c6a7368fdcafbabc3f49f404d6064302cf6aa373c9bad3c73eba126bf5e28167fe92d9cbc466";
		String check_priv = "30d7a9690e56b6d67976ecb7d202a7f56810f3ba13fed13d93652998aacb73c1f911a8a5e3e51f05c75c46563c5e22ca7704160873f123e008c56bead44c8c2a4b76d05aec8aba2569b7091a00efd71ca2e4a857d12fb3e5c54e8200d2d0a16c0460e26e45b53caaab134fb928758b645c93f2b4e01874da8a263452ff975585700f1f878f8eca470b92a8ade5452f9b0077bebef26f963e6e81b4d5321a24ce";
		String check_c = "34f34a515e7ce99edcc8fa94b51ea45b24c5cf9d23a7288252a40ceff9e128ad29f1426c745b495d909fcb99c4d9d79c80cae5deb2df266e262c0f3cafd93849ec14223d61b4b5c417d1e34816aed14b25254214c2cab92318540aa4cf3742e06fb122c17ba893e2947979a8c6c0510801da699b610926290080f061838b4de0c502ad3be73239a362fb332f957aaa3cd7ece681ad78e202cb3e6728af2bb05776187db956414e4eb638015c9957028b088402e3d5eb67775f9cfe2d4032b727fab059dc67f112e41b80ee3a2d878f1a54528e5860fa07addf1c49b8d899b7c449cb99d693f24c7262c2333401a5522743b0e6629902992a0a49a2c1069ee641bcfddb6fe27d068c118889738e9a0bca238ef2113cc6f20ea0d2a670352767cde4f9cef8b254f98c3e4ca0c59c380dbcbeb4d3f9b86117648d77ae6b93884080";

		// add our custom provider
		Security.addProvider(new CryptosystemsProvider());
		KeyPairGenerator generator = null;
		Cipher cipher = null;
		SecureRandom rnd = null;
		try {
			rnd = SecureRandom.getInstance("CryptosystemsRandom");		
			generator = KeyPairGenerator.getInstance("GF");
			cipher = Cipher.getInstance("GFElGamal");
		} catch(Exception ex) { System.out.println("Exception: "); ex.printStackTrace(); };

		// test 1: inversion
		
		GFElement t0 = new GFElement(rnd).inverse();
		System.out.println(t0.toString(16).equals(check_t0) ? "PASS" : "FAIL");

		// test 2-3: key pair generation
		// initialize key pair generator and generate a key pair
		generator.initialize(1279, rnd);
	    KeyPair pair = generator.generateKeyPair();
	    Key pubKey = pair.getPublic();
	    Key privKey = pair.getPrivate();
		System.out.println(((GFPublicKey)(pubKey)).getValue().toString(16).equals(check_pub) ? "PASS" : "FAIL");
		System.out.println(((GFPrivateKey)(privKey)).getValue().toString(16).equals(check_priv) ? "PASS" : "FAIL");
	    
	    byte[] input = {0, 1, 2, 3};
	    byte[] cipherText = null;
	    byte[] plainText = null;
	    
	    // test 4: encryption
	    try {
	    	cipher.init(Cipher.ENCRYPT_MODE, pubKey, rnd);
	    } catch(Exception ex) { System.out.println("Exception: "); ex.printStackTrace(); };
	    try {
	    	cipherText = cipher.doFinal(input);
	    } catch(Exception ex) { System.out.println("Exception: "); ex.printStackTrace(); };
	    System.out.println(byteArrayToHexString(cipherText).equals(check_c) ? "PASS" : "FAIL");

	    // test 5: decryption
	    try {
	    	cipher.init(Cipher.DECRYPT_MODE, privKey);
	    } catch(Exception ex) { System.out.println("Exception: "); ex.printStackTrace(); };
	    try {
	    	plainText = cipher.doFinal(cipherText);
	    } catch(Exception ex) { System.out.println("Exception: "); ex.printStackTrace(); };
	    System.out.println(Arrays.equals(plainText, input) ? "PASS" : "FAIL");
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

