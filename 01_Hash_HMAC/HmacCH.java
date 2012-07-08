import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;

public class HmacCH extends MacSpi {

	//the key for the Hmac
	private byte keyValue[];
	
	//the HMAC
	private byte HMAChash[];
	
	private MessageDigest algorithm = null;

	// IPAD and OPAD key for HMAC
	private byte IPADkey[] = new byte[64];
	private byte OPADkey[] = new byte[64];
	
	//dynamic array for the message to be authenticated
	private List<Byte> macMsg = new ArrayList<Byte>();
	
	
	// constructor for the HMAC function
	public HmacCH() throws NoSuchAlgorithmException {
		try {
			algorithm = MessageDigest.getInstance("CH");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid algorithm - HASH");
			System.exit(-1);
		}

		// initializing IPAD and OPAD keys
		IPADkey[0] = (byte) 0x36;
		OPADkey[0] = (byte) 0x5c;		
	}
		   
	
	//function to compute the HMAC
	protected byte[] engineDoFinal() {

		//for putting the message
		byte msg[] = new byte[macMsg.size()];
		
		//copying the message
		for (int i = 0; i < macMsg.size(); i++) {
			msg[i] = macMsg.get(i);
		}

		//calculating K XOR IPAD and K XOR OPAD
		for (int i = 0; i < keyValue.length; i++) {
			OPADkey[i] ^= keyValue[i];
			IPADkey[i] ^= keyValue[i];
		}
		
		//generating hash of (key xor IPAD) || message
		algorithm.update(IPADkey);
		algorithm.update(msg);
		byte[] hashIPADm = algorithm.digest();

		
		//generating hash of (k xor opad) || hashIPADm
		algorithm.update(OPADkey);
		algorithm.update(hashIPADm);
		HMAChash = algorithm.digest();

		//returning the HMAC
		return HMAChash;
	}


	//function to get the key value for the HMAC
	protected void engineInit(Key key, AlgorithmParameterSpec params) {
		keyValue = key.getEncoded();
	}


	//initializing IPAD and OPAD to its initial state
	protected void engineReset() {

		OPADkey = new byte[64];
		IPADkey = new byte[64];
		
		IPADkey[0] = (byte) 0x36;
		OPADkey[0] = (byte) 0x5c;
	}

	
	//function to update the input message with one byte
	protected void engineUpdate(byte input) {
		macMsg.add(input);
	}

	
	//function to update the input message with a string
	protected void engineUpdate(byte[] input, int offset, int len) {
		for (int i = 0; i < len; i++) {
			engineUpdate(input[i + offset]);
		}

	}

	
	//fucntion to return the length of the HMAC
	protected int engineGetMacLength() {
		return HMAChash.length;
	}

}
