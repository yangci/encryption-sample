import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * BlowFishによる暗号化と復元のサンプル
 *
 * @since 2009-03-24
 * @author Yoji Itoh <yoji@itoh.to>
 */
public class BlowFish {

	private static final String ENCODING = "UTF-8";

	// 32bit - 128bit (448bit)
	private static final String TEST_KEY = "ab4Htd93pBdei30Q";

	/**
	 * コマンドラインからの使い方
	 */
	private static void usage() {
		System.out.println("Usage: java BlowFish <encode|decode> [key] <text>");
		System.exit(-1);
	}

	/**
	 * byte配列を16進数の文字列に変換します。
	 * 
	 * @param bytes
	 *            byte配列
	 * @return 16進数の文字列
	 */
	public static String byteToString(byte[] bytes) {
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i < bytes.length; i++) {
			int d = bytes[i];
			if (d < 0) {
				d += 256;
			}
			if (d < 16) {
				buf.append("0");
			}
			buf.append(Integer.toString(d, 16));
		}

		return buf.toString();
	}

	/**
	 * 16進数の文字列をbyte配列に変換します。
	 * 
	 * @param string
	 *            16進数の文字列
	 * @return byte配列
	 */
	public static byte[] stringToByte(String string) {
		byte[] bytes = new byte[string.length() / 2];
		String b;

		for (int i = 0; i < string.length() / 2; i++) {
			b = string.substring(i * 2, i * 2 + 2);
			bytes[i] = (byte) Integer.parseInt(b, 16);
		}

		return bytes;
	}

	/**
	 * 文字列を暗号キーで暗号化をしたbyte配列を返します。
	 * 
	 * @param key
	 *            暗号キー
	 * @param text
	 *            暗号化する文字列
	 * @return 文字列を暗号化をしたbyte配列
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] encrypt(String key, String text)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {

		SecretKeySpec sksSpec = new SecretKeySpec(key.getBytes(), "Blowfish");
		Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sksSpec);
		byte[] encrypted = cipher.doFinal(text.getBytes(ENCODING));

		return encrypted;
	}

	/**
	 * 暗号化されたbyte配列を暗号キーで復元した文字列を返します。
	 * 
	 * @param key
	 *            暗号キー
	 * @param encrypted
	 *            暗号化されたbyte配列
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public static String decrypt(String key, byte[] encrypted)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {

		SecretKeySpec sksSpec = new SecretKeySpec(key.getBytes(), "Blowfish");
		Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sksSpec);
		byte[] decrypted = cipher.doFinal(encrypted);

		return new String(decrypted, ENCODING);
	}

	/**
	 * コマンドライン用
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		String key;
		String text;

		if (args.length < 2) {
			usage();
		}

		if (args.length == 2) {
			key = TEST_KEY;
			text = args[1];
		} else {
			key = args[1];
			text = args[2];
		}

		String type = args[0].toLowerCase();
		try {
			if (type.equals("encode")) {
				System.out.println("Key = " + key);
				System.out.println("Text = " + text);
				System.out.println("Encrypted = "
						+ byteToString(encrypt(key, text)));
			} else if (type.equals("decode")) {
				System.out.println("Key = " + key);
				System.out.println("Text = " + text);
				System.out.println("Decrypted = "
						+ decrypt(key, stringToByte(text)));
			} else {
				usage();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

