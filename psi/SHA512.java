package psi;

public class SHA512 {

    public static byte[] hash(byte[] data) {
        long h0 = 0x6a09e667f3bcc908L;
        long h1 = 0xbb67ae8584caa73bL;
        long h2 = 0x3c6ef372fe94f82bL;
        long h3 = 0xa54ff53a5f1d36f1L;
        long h4 = 0x510e527fade682d1L;
        long h5 = 0x9b05688c2b3e6c1fL;
        long h6 = 0x1f83d9abfb41bd6bL;
        long h7 = 0x5be0cd19137e2179L;
        
        long[] k = {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 
                0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL, 
                0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 
                0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 
                0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL, 
                0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 
                0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 
                0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 
                0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L, 
                0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 
                0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 
                0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 
                0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL, 
                0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 
                0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 
                0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};
        
        int orig_len = data.length; 
        long orig_len_bits = orig_len * 8; 

        byte[] with_one = new byte[orig_len+1];         
        System.arraycopy(data, 0, with_one, 0, orig_len);
        with_one[with_one.length - 1] = (byte) 0x80;  
        int new_length = with_one.length*8;

        while (new_length % 1024 != 896) {       
            new_length += 8;
        }

        byte[] with_zeros = new byte[new_length/8];
        System.arraycopy(with_one, 0 , with_zeros, 0, with_one.length);

        byte[] output = new byte[with_zeros.length + 16];
        for (int i = 0; i < 8; i++) {
            output[output.length -1 - i] = (byte) ((orig_len_bits >>> (8 * i)) & 0xFF);
        } 
        System.arraycopy(with_zeros, 0 , output, 0, with_zeros.length);
        
        int size = output.length;
        int num_chunks = size * 8 /1024;
        
        for (int i = 0; i < num_chunks; i++) {
            long[] w = new long[80];
            
            for (int j = 0; j < 16; j++) {     
                w[j] = (((long)(output[i*1024/8 + 8*j]) << 56) & 0xFF00000000000000L) | (((long)(output[i*1024/8 + 8*j+1]) << 48) & 0x00FF000000000000L);
                w[j] |= (((long)(output[i*1024/8 + 8*j+2]) << 40) & 0x0000FF0000000000L) | (((long)(output[i*1024/8 + 8*j+3]) << 32) & 0x000000FF00000000L);
                w[j] |= (((long)(output[i*1024/8 + 8*j+4]) << 24) & 0xFF000000L) | (((long)(output[i*1024/8 + 8*j+5]) << 16) & 0xFF0000L);
                w[j] |= ((long)((output[i*1024/8 + 8*j+6]) << 8) & 0xFF00L) | ((long)((output[i*1024/8 + 8*j+7])) & 0xFFL);
            }
            for (int j = 16; j < 80; j++) {
                long s0 = right_rotate(w[j-15], 1) ^ right_rotate(w[j-15], 8) ^ (w[j-15] >>> 7);
                long s1 = right_rotate(w[j-2], 19) ^ right_rotate(w[j-2], 61) ^ (w[j-2] >>> 6);
                w[j] = w[j-16] + s0 + w[j-7] + s1;
            }
            
            long a = h0;
            long b = h1;
            long c = h2;
            long d = h3;
            long e = h4;
            long f = h5;
            long g = h6;
            long h = h7;
            
            for (int j = 0; j < 80; j++) {
                long S1 = right_rotate(e, 14) ^ right_rotate(e, 18) ^ right_rotate(e, 41);
                long ch = (e & f) ^ (~e & g);
                long temp1 = h + S1 + ch + k[j] + w[j];
                long S0 = right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39);
                long maj = (a & b) ^ (a & c) ^ (b & c);
                long temp2 = S0 + maj;
                
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }
                  
            h0 = h0 + a;
            h1 = h1 + b;
            h2 = h2 + c;
            h3 = h3 + d;
            h4 = h4 + e;
            h5 = h5 + f;
            h6 = h6 + g;
            h7 = h7 + h;          
        }

        byte[] hash = new byte[64];
        for (int j = 0; j < 8; j++) {
            hash[j] = (byte) ((h0 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+8] = (byte) ((h1 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+16] = (byte) ((h2 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+24] = (byte) ((h3 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+32] = (byte) ((h4 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+40] = (byte) ((h5 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+48] = (byte) ((h6 >>> (56-j*8)) & 0xFF);
        }
        for (int j = 0; j < 8; j++) {
            hash[j+56] = (byte) ((h7 >>> (56-j*8)) & 0xFF);
        }
        return hash;
    }
    
    private static long right_rotate(long n, long d) {
        return (n >>> d) | (n << (64 - d));
    }

}
