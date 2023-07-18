package psi;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class RSAPsi {

	public static final int BITS = 1024;
	private static final int RAND_LEN = 64;
	private static final int BYTES = 128;
	
	/**
	 * 1. First step.
	 * We generate RSA public key and private key.
	 * Client holds both keys.
	 * Then, client send publicKey to server.
	 * 
	 * return byte[][] {publicKey,privateKey}
	 * */
	public static byte[][] genKeyPair() {
		SecureRandom sr = new SecureRandom();
		BigInteger p1 = BigInteger.probablePrime((BITS >> 1) - 1, sr);
		BigInteger p2 = BigInteger.probablePrime((BITS >> 1) - 1, sr);
		BigInteger n = p1.multiply(p2);
		BigInteger fiN = p1.subtract(BigInteger.ONE).multiply(p2.subtract(BigInteger.ONE));
		BigInteger e = BigInteger.probablePrime(fiN.bitLength(), sr);
		while(e.compareTo(fiN) >= 0) {
			e = BigInteger.probablePrime(fiN.bitLength() - 1, sr);
		}
		BigInteger d = e.modInverse(fiN);
		
		byte[] eb = e.toByteArray(), db = d.toByteArray(), nb = n.toByteArray();
		int l = BYTES << 1;
		byte[] pub = new byte[l], pri = new byte[l];
		System.arraycopy(nb, 0, pub, BYTES - nb.length, nb.length);
		System.arraycopy(eb, 0, pub, l - eb.length, eb.length);
		System.arraycopy(nb, 0, pri, BYTES - nb.length, nb.length);
		System.arraycopy(db, 0, pri, l - db.length, db.length);
		return new byte[][] {pub, pri};
	}
	
	/**
	 * 2. Second step.
	 * Server gets the public key in step 1.(publicKey = {n, e})
	 * Then, for each element(x) in the server's set, we randomly generate r to calculate u = hash512(x) * (r ^ x), mod n.
	 * At last, we get to data set which are set-r(contains randomly generated r) and set-u(which are calculated with hash512(x) * (r ^ e), mod n)
	 * Send set-u to client.
	 * 
	 * return Pair.p0 = uSet, Pair.p1 = rSet
	 * */
	public static Pair server0(byte[] pk, ArrayList<byte[]> set) {
		BigInteger n = new BigInteger(1, Arrays.copyOfRange(pk, 0, BYTES));
		BigInteger e = new BigInteger(1, Arrays.copyOfRange(pk, BYTES, BYTES << 1));
		ArrayList<byte[]> uSet = new ArrayList<>(set.size());
		ArrayList<byte[]> rSet = new ArrayList<>(set.size());
		Random rand = new Random();
		for(byte[] s: set) {
			BigInteger h = new BigInteger(1, SHA512.hash(s)).mod(n);
			byte[] r = new byte[RAND_LEN];
			rand.nextBytes(r);
			rSet.add(r);
			BigInteger c = new BigInteger(1, r).modPow(e, n);
			byte[] u = h.multiply(c).mod(n).toByteArray();
			uSet.add(u);
		}
		return new Pair(uSet, rSet);
	}

	/**
	 * 3. Third step.
	 * Client gets data set set-u in step 2. Also, Client still holds publicKey and privateKey {d, n}.
	 * First, the RSA algorithm shows that m ^ e = c mod n and c ^ d = m mod n.
	 * So, we get z = u ^ d = (hash512(x) * (r ^ e)) ^ d = r * (hash512(x) ^ d), mod n.
	 * Moreover, for each element(y) in the client's set, we calculate b = hash512(hash512(y) ^ d, mod n).
	 * At last, we send both data sets(set-z and set-b) to client.
	 * 
	 * return Pair.p0 = zSet, Pair.p1 = bSet
	 * */
	public static Pair client1(byte[] sk, ArrayList<byte[]> uSet, ArrayList<byte[]> set) {
		BigInteger n = new BigInteger(1, Arrays.copyOfRange(sk, 0, BYTES));
		BigInteger d = new BigInteger(1, Arrays.copyOfRange(sk, BYTES, BYTES << 1));
		ArrayList<byte[]> zSet = new ArrayList<byte[]>(uSet.size());
		for(byte[] u: uSet) {
			byte[] z = new BigInteger(1, u).modPow(d, n).toByteArray();
			zSet.add(z);
		}
		ArrayList<byte[]> bSet = new ArrayList<>(set.size());
		for(byte[] s: set) {
			BigInteger h = new BigInteger(1, SHA512.hash(s)).mod(n);
			byte[] b = h.modPow(d, n).toByteArray();
			int i = 0;
			while(b[i] == 0) {
				i++;
			}
			bSet.add(SHA512.hash(Arrays.copyOfRange(b, i, b.length)));
		}
		return new Pair(zSet, bSet);
	}
	
	
	/**
	 * 4. Forth step.
	 * Server gets both data sets(set-z and set-b) in step 3.
	 * Then, for each element(z) in set-z, we calculate a = z / r = (r * (hash512(x) ^ d)) / r = hash512(x) ^ d, mod n.
	 * The element(b) in set-b is hash512(hash512(x) ^ d, mod n).
	 * At last, we just need to calculate hash512(a) = hash12(hash512(x) ^ d, mod n), and compare it to b.
	 * By comparing hash512(a) and b, we get the intersection.
	 * 
	 * return intersection.
	 * */
	public static ArrayList<byte[]> server2(byte[] pk, ArrayList<byte[]> zSet, ArrayList<byte[]> bSet, ArrayList<byte[]> rSet) {
		BigInteger n = new BigInteger(1, Arrays.copyOfRange(pk, 0, BYTES));
		ArrayList<byte[]> psiSet = new ArrayList<>(zSet.size());
		Intersection insec = new Intersection(bSet);
		int i = 0;
		for(byte[] z: zSet) {
			byte[] a = new BigInteger(1, z)
					.multiply(new BigInteger(1, rSet.get(i++)).modInverse(n))
					.mod(n)
					.toByteArray();
			int j = 0;
			while(a[j] == 0) {
				j++;
			}
			byte[] h = SHA512.hash(Arrays.copyOfRange(a, j, a.length));
			if(insec.contains(h)) {
				psiSet.add(h);
			}
		}
		return psiSet;
	}
	
	public static class Pair {
		ArrayList<byte[]> p0;
		ArrayList<byte[]> p1;
		
		public Pair(ArrayList<byte[]> p0, ArrayList<byte[]> p1) {
			super();
			this.p0 = p0;
			this.p1 = p1;
		}
		public ArrayList<byte[]> getP0() {
			return p0;
		}
		public void setP0(ArrayList<byte[]> p0) {
			this.p0 = p0;
		}
		public ArrayList<byte[]> getP1() {
			return p1;
		}
		public void setP1(ArrayList<byte[]> p1) {
			this.p1 = p1;
		}
	}
	
	/**
	 * Here, we simply use array(as a map) and bloom filter to get the inspection.
	 * */
	static class Intersection {
		
		private static final int P = 128;
		
		N[] map;
		byte[] bloom = new byte[BITS / 8];
		
		//512 bits input
		public Intersection(List<byte[]> set) {
			int m = set.size() / P + 1;
			map = new N[m];
			for(byte[] s: set) {
				for(int i = 0; i < bloom.length; i++) {
					bloom[i] = (byte) (bloom[i] | s[i]);
				}
				long p = 0;
				for(int i = 0; i < 7; i++) {
					long l = (long) s[i];
					if(l < 0) {
						l += 256;
					}
					p |= (l << ((6 - i) << 3));
				}
				int r = (int) (p % m);
				if(map[r] == null) {
					map[r] = new N(s);
				} else {
					N cur = new N(s);
					map[r].next = cur;
					cur.last = map[r];
					map[r] = cur;
				}
			}
		}
		
		public boolean contains(byte[] bs) {
			for(int i = 0; i < bloom.length; i++) {
				if(bloom[i] == 0 && bs[i] == 1) {
					return false;
				}
			}
			long p = 0;
			for(int i = 0; i < 7; i++) {
				long l = (long) bs[i];
				if(l < 0) {
					l += 256;
				}
				p |= (l << ((6 - i) << 3));
			}
			int m = map.length;
			int r = (int) (p % m);
			N cur = map[r];
			while(cur != null) {
				byte[] d = cur.data;
				boolean ok = true;
				for(int i = 0; i < bloom.length; i++) {
					if(d[i] != bs[i]) {
						ok = false;
						break; 
					}
				}
				if(ok) {
					return true;
				}
				cur = cur.last;
			}
			return false;
		}
	}
	
	static class N {
		byte[] data;
		N last;
		N next;
		
		public N(byte[] data) {
			this.data = data;
		}
	}
}
