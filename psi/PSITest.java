package psi;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import psi.RSAPsi.Pair;

public class PSITest {

	
	public static void csvTest() {
		try {
			byte[] f1Bytes = Files.readAllBytes(Paths.get("1.csv"));
			byte[] f2Bytes = Files.readAllBytes(Paths.get("2.csv"));
			
			String f1 = new String(f1Bytes, StandardCharsets.UTF_8);
			String[] f1Lines = f1.split("\n");
			ArrayList<byte[]> id1List = new ArrayList<>(f1Lines.length);  //id1s
			for(int i = 1; i < f1Lines.length; i++) {
				String l = f1Lines[i].trim();
				if(!l.equals("")) {
					String[] lsep = l.split(",");
					id1List.add(lsep[2].getBytes(StandardCharsets.UTF_8));
				}
			}
			
			String f2 = new String(f2Bytes, StandardCharsets.UTF_8);
			String[] f2Lines = f2.split("\n");
			ArrayList<byte[]> id2List = new ArrayList<>(f1Lines.length);  //id2s
			for(int i = 1; i < f2Lines.length; i++) {
				String l = f2Lines[i].trim();
				if(!l.equals("")) {
					String[] lsep = l.split(",");
					id2List.add(lsep[2].getBytes(StandardCharsets.UTF_8));
				}
			}
			
			byte[][] sp = RSAUtil.genKeyPair();
			byte[] pk = sp[0], sk = sp[1];

			long t0 = System.currentTimeMillis();
			Pair pair0 = RSAPsi.server0(pk, id1List);
			long t1 = System.currentTimeMillis();
			
			Pair pair1 = RSAPsi.client1(sk, pair0.getP0(), id2List);
			long t2 = System.currentTimeMillis();
			
			ArrayList<byte[]> psiSet = RSAPsi.server2(pk, pair1.getP0(), pair1.getP1(), pair0.getP1());
			long t3 = System.currentTimeMillis();
			
			
			System.out.println("cost = " + (t1 - t0) + "ms");
			System.out.println("cost = " + (t2 - t1) + "ms");
			System.out.println("cost = " + (t3 - t2) + "ms");
			System.out.println("total cost = " + (t3 - t0) + "ms");
			System.out.println("psi size = "+psiSet.size());
			
			Path dst =  Paths.get("E:/psi.txt");
			for(byte[] p: psiSet) {
				Files.write(dst, p, StandardOpenOption.APPEND);
				Files.write(dst, "\n".getBytes(), StandardOpenOption.APPEND);
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	
	public static void test() {
		ArrayList<byte[]> set1 = new ArrayList<>(5);
		ArrayList<byte[]> set2 = new ArrayList<>(5);
		
		
		set1.add("nihao1".getBytes());
		set1.add("nihao2".getBytes());
		set1.add("nihao3".getBytes());
		set1.add("nihao4".getBytes());
		set1.add("nihao5".getBytes());
		

		set2.add("nihao1".getBytes());
		set2.add("nihao3".getBytes());
		set2.add("nihao5".getBytes());
		set2.add("nihao7".getBytes());
		set2.add("nihao9".getBytes());
		
		

		byte[][] sp = RSAUtil.genKeyPair();
		byte[] pk = sp[0], sk = sp[1];
		
		long t0 = System.currentTimeMillis();
		Pair pair0 = RSAPsi.server0(pk, set1);
		long t1 = System.currentTimeMillis();
		
		Pair pair1 = RSAPsi.client1(sk, pair0.getP0(), set2);
		long t2 = System.currentTimeMillis();
		
		ArrayList<byte[]> psiSet = RSAPsi.server2(pk, pair1.getP0(), pair1.getP1(), pair0.getP1());
		long t3 = System.currentTimeMillis();
		
		
		System.out.println("cost = " + (t1 - t0) + "ms");
		System.out.println("cost = " + (t2 - t1) + "ms");
		System.out.println("cost = " + (t3 - t2) + "ms");
		System.out.println("total cost = " + (t3 - t0) + "ms");
		System.out.println("psi size = "+psiSet.size());
	}
	
	public static void main(String[] args) {
		csvTest();
	}
}
