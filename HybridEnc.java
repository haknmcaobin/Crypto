import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.sun.xml.internal.messaging.saaj.util.Base64;


public class Encrypt {
	
	static int leftNo;
	static int blkNo;
	
	public static String AES_CBC_ENC(String IV, String data, String kenc, String kmac) throws Exception{
		
		//Encrypt the plain text with CBC
		
		byte[] m2 = pkcs5(data, kmac);
		//System.out.println("m2_enc is:     "+new BASE64Encoder().encode(m2));
		byte pblock[][]= plainblock(m2);
		byte[] finalcomb = new byte[16*blkNo];
		int n = blkNo;
		byte[][] cblock= new byte[n][16];
		cblock[0] = AES_ECB_ENC(xor(pblock[0],IV.getBytes()),kenc);
		for(int i=1;i<n;i++){
			cblock[i] = AES_ECB_ENC(xor(pblock[i],cblock[i-1]),kenc);
		}
		for(int i=0;i<blkNo;i++){
			for(int j=0;j<16;j++){
				finalcomb[16*i+j] = cblock[i][j];
			}
		}
		byte[] finalcipher = join(IV.getBytes(), finalcomb);
		//System.out.println("Final is: "+new String(finalcipher));
	    String enc_base64byte = new BASE64Encoder().encode(finalcipher);
	    //byte [] rev = new BASE64Decoder().decodeBuffer(enc_base64byte);
	    //if(new String(finalcipher)==new String(rev)){
	    //System.out.println("Final rev is: "+new String(rev));
	    //}
		return enc_base64byte;
	}
	
	public static void AES_CBC_DEC(String data, String kenc, String kmac) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		
		//Decrypt the cipher block with CBC
		int n = blkNo;
		byte[] C2 = new BASE64Decoder().decodeBuffer(data);
		//System.out.println("C2 is: "+new String(C2));
		byte[] IV_dec = new byte[16];
		byte[] C1 = new byte[C2.length - 16];
		for(int i=0;i<16;i++){
			IV_dec[i] = C2[i];
		}
		for(int i=16;i<C2.length;i++){
			C1[i-16] = C2[i];
		}
		//System.out.println("IV_dec="+new BASE64Encoder().encode(IV_dec));
		byte[][] Pblk = new byte[n][16];
		byte[][] Cblk = new byte[n][16];
		for(int i=0;i<blkNo;i++){
			for(int j=0;j<16;j++){
				Cblk[i][j] = C1[16*i+j];
			}
		}
		Pblk[0] = xor(AES_ECB_DEC(Cblk[0],kenc),IV_dec);
		for(int i=1;i<n;i++){
			//Pblk[i] = AES_ECB_ENC(xor(pblock[i],cblock[i-1]),kenc);
			Pblk[i] = xor(AES_ECB_DEC(Cblk[i],kenc),Cblk[i-1]);
		}
		byte[] M2 = new byte[16*blkNo];
		byte[] M1 = new byte[16*blkNo+leftNo-16];
		for(int i=0;i<blkNo;i++){
			for(int j=0;j<16;j++){
				M2[16*i+j] = Pblk[i][j];
			}
		}
		//System.out.println("M2_dec is:    "+new BASE64Encoder().encode(M2));

		// M' = M''-PS
		for(int i=16*blkNo-1;i>16*blkNo-1-16+leftNo;i--){
			if(M2[i]!=(byte)(16-leftNo)){
				System.out.println("INVALID PADDING");
				break;
			}
		}
		for(int j=0;j<16*blkNo-16+leftNo;j++){
			M1[j] = M2[j];
			}		
		//System.out.println("M1_dec is:    "+new BASE64Encoder().encode(M1));
		
		//Parse M′ as M||T where T is a 20-byte HMAC-SHA1 tag,M = M'-T
		
		byte[] M = new byte[16*blkNo+leftNo-16-20];
		byte[] T = new byte[20];
		
		for(int i = 0;i<16*blkNo+leftNo-16-20;i++){
			M[i] = M1[i];
		}
		//System.out.println("M_dec is:    "+new BASE64Encoder().encode(M));
		for(int i =16*blkNo+leftNo-16-20;i<16*blkNo+leftNo-16;i++){
			T[i-16*blkNo-leftNo+16+20] = M1[i];
		}
		System.out.println("T_dec is:    "+new BASE64Encoder().encode(T));
		byte[] T1 = new byte[20];
		T1 = getHMACSHA1(M,kmac);
		System.out.println("Tag T' is: "+new BASE64Encoder().encode(T1));
		for(int i=0;i<20;i++){
			if(T[i] != T1[i]){
				System.out.println("INVALID MAC");
				break;}
		}
		System.out.println("\n\nSuccessful decryption!\n\n"+new BASE64Encoder().encode(M));
		
		return;
	}
	
	public static byte[] AES_ECB_ENC(byte[] data, String kenc) throws Exception {
		byte[] raw = kenc.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(data);
 
        return encrypted;
	}
	
	public static byte[] AES_ECB_DEC(byte[] data, String kenc) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		byte[] raw = kenc.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(data);
        return decrypted;
        }
	
	public static byte[] getHMACSHA1(byte[] m0, String kmac) throws NoSuchAlgorithmException{
		
		//use HMACSHA1 output 20-byte MAC tag T
		
		byte[] ipad = new byte[64];
		byte[] opad = new byte[64];
		byte[] keyArray = new byte[64];
		MessageDigest md =MessageDigest.getInstance("SHA1");
		int ex = kmac.length();
		if(kmac.length()>64){
			byte[] temp = md.digest(kmac.getBytes());
			ex = temp.length;
			for(int i = 0; i < ex; i++){keyArray[i]=temp[i];}
		}else{
			byte[] temp = kmac.getBytes();
			for(int i = 0; i< temp.length; i++){keyArray[i]=temp[i];}
		}
		for(int i = ex; i < 64; i++){keyArray[i]=0;}
		for(int j = 0; j <64; j++){
			ipad[j] = (byte)(keyArray[j]^ 0x36);
			opad[j] = (byte)(keyArray[j]^ 0x5c);
		}
		byte[] tempout = md.digest(join(ipad,m0));
		return md.digest(join(opad,tempout));
	}
	
	public static byte[] pkcs5(String data,String kmac) throws NoSuchAlgorithmException{
		
		byte[] tag = getHMACSHA1(data.getBytes(),kmac);
		//System.out.println("t_enc is:    "+new BASE64Encoder().encode(tag));
		
		//M' = M||T
		
		byte[] m_enc = data.getBytes();
		//System.out.println("m_enc is:    "+new BASE64Encoder().encode(m_enc));
		byte[] m1 = join(data.getBytes(),tag);
		//System.out.println("m1_enc is:     "+new BASE64Encoder().encode(m1));
		byte[] m2;
		
		//padding for the M''=M'||PS
		
		leftNo = (m1.length)%16;
		if(leftNo == 0){
			byte[] PS = new byte[16];
			for(int i=0;i<16;i++){ PS[i]=0x10;}
			m2 = join(m1,PS);
		}
		else{
			byte[] PS = new byte[16-leftNo];
			for(int i=0;i<16-leftNo;i++){ PS[i]=(byte)(16-leftNo);}
			m2 = join(m1,PS);
		}
		System.out.println("The left number is: "+leftNo);
		return m2;
		}
	
	public static byte[] xor(byte[] a, byte[] b){
		
		//XOR between 2 byte arrays
		
		byte[] xorbyte= new byte[16];
		for(int i=0;i<16;i++){
			xorbyte[i]=(byte)(a[i]^b[i]);
		}
		return xorbyte;
	}
	
	
	public static byte[][] plainblock(byte[] plaintext){
		
		//Block the plain text for CBC
		
		blkNo = (plaintext.length)/16;
		
		System.out.println("The plaintext length is: "+plaintext.length);
		byte[][] cblock=new byte[blkNo][16];
		for(int i=0;i<blkNo;i++){
			for(int j=0;j<16;j++){
			cblock[i][j] = plaintext[i*16+j];
			}
		}
		System.out.println("The block number is: "+blkNo);
		return cblock;
	}
	
	public static byte[] join(byte[] b1, byte[] b2){
		
		//Combine 2 byte arrays   a||b
		
		int length = b1.length+b2.length;
		byte[] comb = new byte[length];
		for(int i=0;i<b1.length;i++){comb[i]=b1[i];}
		for(int i=0;i<b2.length;i++){comb[i+b1.length]=b2[i];}
		return comb;
	}

	public static void main(String[] args) throws Exception{
		String data = "Bin Cao's HW2-1, you can change these input data, kenc kmac and iv";
		String kenc = "qwqwqADSqwqwqwqw";
		String kmac = "dfregthijvmbldxs";
		String IV = "etyjklxcdvfghnjy";
		String s_enc = AES_CBC_ENC(IV, data, kenc, kmac);
		System.out.println("The ciphertxt encrypted by AES-CBC-HMAC-SHA1 is: "+s_enc);
		AES_CBC_DEC(s_enc, kenc, kmac);
}
}
