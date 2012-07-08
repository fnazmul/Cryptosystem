import java.security.*;

public class CHMessageDigest extends MessageDigest {

	// the variable on which CH algorithm is performed
	private int state[] = new int[32];
	
	
	//constructor for the CH hash function
	public CHMessageDigest() {
		
		super("CHMessageDigest");
		// performing initialization
		engineReset();
	}

	
	//resetting the state variable to its initial state
	protected void engineReset() {
				
		stateInitialization();

	}

	
	//function to perform the hash function
	protected byte[] engineDigest() {
		
		//64 bytes of hash
        byte hashValue[] = new byte[64];
		
		//engine update .. called automatically
			// for each block, XOR the block into state word x00000
			// perform 8 rounds of state transformation
		
		//padding the message i.e. appending 128 as a byte to the message
		stateUpdate((byte) 128);
		
		//performing finalization on the state
		stateFinalization();
		
		//taking the first 64 bytes as the hash
		// changing from little-endian to big-endian
		for (int j = 0; j < 16; j++) {
            hashValue[j*4]     = (byte) (state[j] >>> 0);
            hashValue[j*4 + 1] = (byte) (state[j] >>> 8);
            hashValue[j*4 + 2] = (byte) (state[j] >>> 16);
            hashValue[j*4 + 3] = (byte) (state[j] >>> 24);
        }
		
		//resetting the state of the engine
		engineReset();
		
		//returning the hashValue
		return hashValue;

	}

	
	//function to update the state with one byte
    protected void engineUpdate(byte b) {
		//updating the state for this block of message
		stateUpdate( b );

	}

    
    //function to update the state with series of bytes
    protected void engineUpdate(byte b[], int offset, int length) {
		//updating the state for each block of message
		for (int i = 0; i < length; i++) {
            stateUpdate(b[i+offset]);
        }

	}
	

	
	//function to perform the state transformation for iterationNum times
	 private void stateTransformation(int iterationNum) {

		 //2^32 to use as the modulo value
		 double moduloValue = Math.pow(2.0, 32.0);

		 for (int rnd = 0; rnd < iterationNum; rnd++) {

	            //step1. Adding x0jklm into x1jklm modulo 2^32 for each (j, k, l, m)
	            for (int i = 0; i < 16; i++) {
	                state[i+16] = (int) ((state[i+16] + state[i]) % moduloValue);
	            }

	            //step2. Rotating x0jklm up 7 bits for each (j, k, l, m)
	            for (int i = 0; i < 16; i++) {
	            	// shifted 7bits to the left and took the remaining value and 
	            	// OR it with the value of first 7 bits
	                state[i] = state[i] << 7  | state[i] >>> (32-7) ;
	            }

	            //step3. Swapping x00klm and x01klm for each (k, l, m)
	            for (int i = 0; i < 8; i++) {
	                state[i] ^= state[i+8];
	                state [i+8] ^=state[i];
	                state[i] ^= state[i+8];
	            }

	            //step4. XORing x1jklm into x0jklm for each (j, k, l, m)
	            for (int i = 0; i < 16; i++) {
	                state[i] ^= state[i+16];
	            }

	            //step5. Swapping x1jk0m and x1jk1m for each (j, k, m)	            
	            for (int j = 16; j < 32; j += 4) {
	                state[j] ^= state[j+2];
	                state[j+2] ^= state[j];
	                state[j] ^= state[j+2];

	                state[j+1] ^= state[j+3];
	                state[j+3] ^= state[j+1];
	                state[j+1] ^= state[j+3];
	            }

	            //step6. Adding x0jklm into x1jklm modulo 2^32 for each (j, k, l, m)
	            for (int i = 0; i < 16; i++) {
	                state[i+16] = (int) ((state[i+16] + state[i]) % moduloValue);
	            }

	            //step7. Rotating x0jklm up 11 bits for each (j, k, l ,m)
	            for (int i = 0; i < 16; i++) {
	            	// shifted 11bits to the left and took the remaining value and 
	            	// OR it with the value of first 11 bits
	                state[i] = state[i] << 11 | state[i] >>> (32 - 11);
	            }

	            //step8. Swapping x0j0lm and x0j1lm for each (j, l, m)
	            for (int i = 0; i < 4; i++) {
	                state[i] ^= state[i+4];
	                state[i+4] ^= state[i];
	                state[i] ^= state[i+4];

	                state[i+8] ^= state[i+12];
	                state[i+12] ^= state[i+8];
	                state[i+8] ^= state[i+12];
	            }

	            //step9. XORing x1jklm into x0jklm for each (j, k, l, m)
	            for (int i = 0; i < 16; i++) {
	                state[i] ^= state[i+16];
	            }

	            //step10. Swapping x1jkl0 and x1jkl1 for each (j, k, l)
	            for (int j = 16; j < 32; j += 2) {
	                state[j] ^= state[j+1];
	                state[j+1] ^= state[j];
	                state[j] ^= state[j+1];
	            }
	        }
	    }
	 
	 
	 //function to perform the initialization
	 protected void stateInitialization() {
			
			// initializing the state with 0s
	    	state = new int[32];
	    	
	    	//setting the first three words to 64, 1 and 8 respectively
	    	state[0] = 64;
	        state[1] = 1;
	        state[2] = 8;
	        
	        // performing 80 rounds of state transformation
	        stateTransformation(80);
	        
	}

     
	 //function to update the state for each block of message
	 private void stateUpdate(byte b){

		//for each block, XOR the block into state word x00000
		state[0] ^= (int) b & 0xff;

		//performing 8 rounds of state transformation
        stateTransformation(8);
        
	}

    
	private void stateFinalization() {

        //XOR 1 as a byte into state word x11111
        state[31] ^= (byte) 1;

        //Performing 80 rounds of state transformation.
        stateTransformation(80);
    }
   
}
