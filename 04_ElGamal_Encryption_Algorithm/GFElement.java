import java.math.BigInteger;
import java.util.Random;

/**
 * Immutable class representing elements of the finite field GF(2^1279).
 * Realized by GF(2^1279) = GF(2)[x]/(x^1279 + x^319 + x^127 + x^63 + 1).
 * You'll probably store it in a BigInteger:
 * http://java.sun.com/javase/6/docs/api/java/math/BigInteger.html
 * @author You
 */
public class GFElement {
	
	public BigInteger current;	
			
	/**
	 * Given a = \sum_{i=0}^{1278}a_i 2^i construct the polynomial \sum_{i=0}^{1278}a_i x^i
	 * @param a radix-2 representation of the polynomial
	 */
	public GFElement(BigInteger a) {
		current = a;
	}

	
	/**
	 * Construct a random element of the finite field.
	 * @param rnd
	 */
	public GFElement(Random rnd)  {
		current = new BigInteger(1279, rnd);
	}
	
	/**
	 * Construct the element represented in big-endian by the bytes in val.
	 * Compatible with the corresponding BigInteger constructor.
	 * @param val byte array representation of the field element
	 */
	public GFElement(byte[] val) {
		current = new BigInteger(val);
	}
	
	
	/**
	 * Construct element from string in given base
	 * @param s string representation
	 * @param radix base
	 */
	public GFElement(String s, int radix) {
		current = new BigInteger(s, radix);
	}
	
	
	/**
	 * Add two elements of the finite field; just XOR
	 * @param a field element
	 * @return the sum this + a
	 */
	public GFElement add(GFElement a) {
		GFElement result = new GFElement(current.xor(a.current));
		return result;
	}
	
	
	/**
	 * Multiply two elements of the finite field.
	 * @param a field element
	 * @return the product this * a
	 */
	public GFElement multiply(GFElement a) {
		
		//f(x) = x^1279 + x^319 + x^127 + x^63 + 1
		BigInteger fX = irreduciblePolynomial();	
		
		BigInteger accumulator;
		// this
		BigInteger multiplicand = current;
		// a
		BigInteger multiplier = a.current;
				
		if(multiplicand.testBit(0) == true)
			accumulator = multiplier;
		else
			 accumulator = BigInteger.ZERO;
		
		for( int i = 1; i <= 1279; i++){
		
			multiplier = multiplier.shiftLeft(1);
			
			if(multiplier.testBit(1279) == true)
				multiplier = multiplier.xor(fX);
			
			if(multiplicand.testBit(i) == true)
				accumulator = accumulator.xor(multiplier);
		}
		
		GFElement result = new GFElement(accumulator);
		return result;	
		
	}
	
	
	/**
	 * Exponentiation in the multiplicative group of the finite field.
	 * @param e integer exponent
	 * @return this^e
	 */
	public GFElement pow(BigInteger e) {
		
		GFElement accumulator = new GFElement(BigInteger.ONE);
		GFElement S = new GFElement(current);
		BigInteger Z = BigInteger.ZERO;
		
		while (e.equals(Z) == false){
			if(e.testBit(0) == true)
				accumulator = accumulator.multiply(S);
			e = e.shiftRight(1);
			if(e.equals(Z) == false)
				S = S.multiply(S);			
		}      
        return accumulator;
        
	}

	
	/**
	 * Inverse of this field element; implement the extended Euclidean algorithm
	 * 
	 * @return z such that z * this = 1
	 */
	public GFElement inverse() {

				
		BigInteger b = BigInteger.ONE;
		BigInteger c = BigInteger.ZERO;
		BigInteger u = this.current;
		// v is for f(x) = x^1279 + x^319 + x^127 + x^63 + 1
		BigInteger v = irreduciblePolynomial();
		
		BigInteger O = BigInteger.ZERO;
		O = O.setBit(0);
		
		BigInteger t;
		int j = 1;
		
		//while deg(u) does not equal to 0
		while ( u.equals(O) == false) {
			
			//j = deg(u) - deg(v)
			j = u.bitLength() - v.bitLength();
			
			if (j < 0) {
				// u <---> v
				t = u;
				u = v;
				v = t;
				
				// b <---> c
				t = b;
				b = c;
				c = t;
				
				j = -j;
			}
			
			// u = u + x^j * v
			u = u.xor(v.shiftLeft(j));
			// b = b + x^j * c
			b = b.xor(c.shiftLeft(j));			
		}
		
		GFElement result = new GFElement(b);
		return result;
	}
	
	
	/**
	 * A default string for field elements; base 2 or 16 are handy.
	 */
	public String toString() {
		return current.toString();
	}

	
	/**
	 * String representation of the field element in some radix.
	 * @param radix the base
	 * @return (this)_r
	 */
	public String toString(int radix) {
		return current.toString(radix);
	}
	
	
	/**
	 * returns true if this equals o
	 * **NOTE**: make sure this is implemented right, or
	 * the driver will lie to you. We WILL check this.
	 */
	public boolean equals(Object o) {
		
		if(!(o instanceof GFElement)) 
			return false;
		
		GFElement obj = (GFElement) o;
		if (current.equals(obj.current))
			return true;
		else
			return false;
		
	}
	
	
	/**
	 * function to generate the irreducible polynomial f(x)
	 */
	public BigInteger irreduciblePolynomial(){
		
		//f(x) = x^1279 + x^319 + x^127 + x^63 + 1		
		BigInteger funcX = BigInteger.ZERO;
		funcX = funcX.setBit(1279);
		funcX = funcX.setBit(319);
		funcX = funcX.setBit(127);
		funcX = funcX.setBit(63);
		funcX = funcX.setBit(0);		
		
		return funcX;
		
	}
	
	
}
