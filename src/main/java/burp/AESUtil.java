package burp;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** 
 *AES加密解密工具类 
 */  
public class AESUtil {  
      private static final String defaultCharset = "UTF-8";  
      private static final String KEY_AES = "AES";  
      public static final String KEY = "XXXXXX";   // AES key to do ENC/DEC, you may have to change this.
      public static final String owner = "XXXXXXX"; // this is required by specific task.
      public static final String head_pass = "XXXXXXX"; // this is required by specific task.
    
/** 
     * 加密 
     * 
     * @param data 需要加密的内容 
     * @param key 加密密码 
     * @return 
     */  
    public static String encrypt(String data, String key) {  
        return doAES(data, key, Cipher.ENCRYPT_MODE);  
    }  
  
    /** 
     * 解密 
     * 
     * @param data 待解密内容 
     * @param key 解密密钥 
     * @return 
     */  
    public static String decrypt(String data, String key) {  
        return doAES(data, key, Cipher.DECRYPT_MODE);  
    }  
  
    /** 
     * 加解密 
     * 
     * @param data 待处理数据 
     * @param password  密钥 
     * @param mode 加解密mode 
     * @return 
     */  
    private static String doAES(String data, String key, int mode) {  
        try {  
            if (data == null || "".equals(data) || key == null || "".equals(key)){
            	return null;
            }  
            boolean encrypt = mode == Cipher.ENCRYPT_MODE;  
            byte[] content;  
            if (encrypt) {  
                content = data.getBytes(defaultCharset);  
            } else {  
                content = parseHexStr2Byte(data);  
            }  
            KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);  
            kgen.init(128, new SecureRandom(key.getBytes()));  
            SecretKey secretKey = kgen.generateKey();  
            byte[] enCodeFormat = secretKey.getEncoded();  
            SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_AES);  
            Cipher cipher = Cipher.getInstance(KEY_AES);// 创建密码器  
            cipher.init(mode, keySpec);// 初始化  
            byte[] result = cipher.doFinal(content);  
            if (encrypt) {  
                return parseByte2HexStr(result);  
            } else {  
                return new String(result, defaultCharset);  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }  
    /** 
     * 将二进制转换成16进制 
     * 
     * @param buf 
     * @return 
     */  
    private static String parseByte2HexStr(byte buf[]) {  
        StringBuilder sb = new StringBuilder();  
        for (int i = 0; i < buf.length; i++) {  
            String hex = Integer.toHexString(buf[i] & 0xFF);  
            if (hex.length() == 1) {  
                hex = '0' + hex;  
            }  
            sb.append(hex.toUpperCase());  
        }  
        return sb.toString();  
    }  
    /** 
     * 将16进制转换为二进制 
     * 
     * @param hexStr 
     * @return 
     */  
    private static byte[] parseHexStr2Byte(String hexStr) {  
        if (hexStr.length() < 1) {  
            return null;  
        }  
        byte[] result = new byte[hexStr.length() / 2];  
        for (int i = 0; i < hexStr.length() / 2; i++) {  
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);  
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);  
            result[i] = (byte) (high * 16 + low);  
        }  
        return result;  
    }  
    
    /**
	 * 实现SHA-256加密
	 * @param str
	 * @return 加密后的报文
	 */
	public static String signBySHA256 (String str) {
		MessageDigest messageDigest;
		String encodeStr = "";
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(str.getBytes("UTF-8"));
			encodeStr = byte2Hex(messageDigest.digest());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return encodeStr;
	}

	/**
	 * 将byte转为16进制
	 * @param bytes
	 * @return
	 */
	private static String byte2Hex(byte[] bytes) {
		StringBuffer stringBuffer = new StringBuffer();
		String temp = null;
		for (int i = 0; i < bytes.length; i++) {
			temp = Integer.toHexString(bytes[i] & 0xFF);
			if (temp.length() == 1) {
				stringBuffer.append("0");
			}
			stringBuffer.append(temp);
		}
		return stringBuffer.toString();
	} 
}
