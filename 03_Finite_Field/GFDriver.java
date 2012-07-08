import java.math.BigInteger;
import java.util.Random;

public class GFDriver {
	public static void main(String[] args) {

		GFElement a = new GFElement("175E699D141A4617619D35529B3B7C351DCFBB1B4BDDD28A9F71F0AEDB3DA23636F5116FE21F6F72BCDCB66664C09EDF75B69A48E978945DDB688A68BE8506ABB7436E13D727B9982D34F6AB203332B8879282896EF5DF797FCEDD2CD9E9F7C15CDCDB0635E6E149AF4D0A4C5C1EBD9D84AAF6FCDB7557D00149E61C743AC5795BDC0859A82A229D0A2C46E6F566C8BB1860C1FA43DFA1D60B922A5894CCBA66",16);
		GFElement b = new GFElement("41DD3E8F2D5907DB80A066A9052585C509D9C08E6201A4208A5F505F03FC8B56D1F187FD245C009EA4BE7A0A69594A3D1A51C93F00528552531056A2DAFA703A1128BEA051D9931A0DAA7BB8E8C7B7042A0F4982EC6A2928B83EC7B1384FB7DF82DD4792720BD4FC6CCAE256855320909122CF0EF4628FE546AD72AFA180FEE83DF84E4602C3460BCB0A47DEE5C190EA2DDEF46FE756F4558FA3193D212CB2F5",16);
		GFElement check = new GFElement("6C93A5EFCCDDBC0AC7D397B376D669B0DE7BDDB1EAAE9E8E204456286B7D531A0F86D600077EB9BF99C34CB21A0C0000D650FE4011008EC2E34C8632873A5AB8123C89C9EFB10AF9EAE8CF43082F472ACB9D071C8D6CF9C796B161B2071A7CCB748AC5D82409A33F183F6E673E8519ED258696116348E4556E5B6BDAC531E3B49AADF5A79425EC7DD58D45E75D6EDFD25BC18CA04B8291542C5F468B3DF70052",16);
		GFElement checkexp = new GFElement("7B3B91E7B60D418FFDC3C1AAD3CD8010E8FE4CDB5208091D2F6202C4204B6CD2744CA69F46AEAF3D88EA54205E4634EDF949431E934271FE9E50515076DD1CF979E7A6B3BF2DAC97C9186CD9C8740F5E11665182A3DC879D7AA0E653020E1B327015DF7E23BFD9B012811C2A141AF09F1563EC121497C50B527D5EC8C1505D09DD101B5793AB10EF8E951AC27F91A692583ADB555F1284D97FCB0A61F42EB58D",16);
		GFElement zero = new GFElement(BigInteger.ZERO);
		GFElement one = new GFElement(BigInteger.ONE);

		// test 1: general multiplication
		System.out.println(a.multiply(b).equals(check) ? "PASS" : "FAIL");

		// test 2: multiplication by zero
		System.out.println(a.multiply(zero).equals(zero) ? "PASS" : "FAIL");
		
		// test 3: multiplication by one
		System.out.println(a.multiply(one).equals(a) ? "PASS" : "FAIL");
		
		// test 4: general exponentiation
		System.out.println(a.pow(new BigInteger(b.toString(16),16)).equals(checkexp) ? "PASS" : "FAIL");

		// test 5: power 0
		System.out.println(a.pow(BigInteger.ZERO).equals(one) ? "PASS" : "FAIL");
		
		// test 6: power 1
		System.out.println(a.pow(BigInteger.ONE).equals(a) ? "PASS" : "FAIL");

		// test 7: power 2
		System.out.println(a.pow(BigInteger.valueOf(2)).equals(a.multiply(a)) ? "PASS" : "FAIL");
		
		// test 8: power 2^m
		System.out.println(a.pow(BigInteger.ZERO.flipBit(1279)).equals(a) ? "PASS" : "FAIL");
		
		// test 9: inverse
		System.out.println(a.pow(BigInteger.ZERO.flipBit(1279).subtract(BigInteger.valueOf(2))).multiply(a).equals(one) ? "PASS" : "FAIL");

	}
}
