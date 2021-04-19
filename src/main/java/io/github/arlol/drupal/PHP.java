package io.github.arlol.drupal;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.springframework.security.crypto.codec.Hex;

public abstract class PHP {

	private PHP() {
	}

	public static byte[] concat(CharSequence a, CharSequence b) {
		return concat(a.toString().getBytes(UTF_8), b);
	}

	public static byte[] concat(byte[] a, CharSequence b) {
		return concat(a, b.toString().getBytes(UTF_8));
	}

	public static byte[] concat(byte[] a, byte[] b) {
		return ByteBuffer.allocate(a.length + b.length).put(a).put(b).array();
	}

	public static String md5(CharSequence string) {
		return bin2hex(hash("MD5", string));
	}

	public static byte[] hash(String algo, CharSequence data) {
		return hash(algo, data.toString().getBytes(UTF_8));
	}

	public static byte[] hash(String algo, byte[] data) {
		try {
			MessageDigest md = MessageDigest.getInstance(algo);
			md.update(data);
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public static int ord(byte[] b) {
		return ord(b[0]);
	}

	public static int ord(byte b) {
		if (b < 0) {
			return 256 + b;
		} else {
			return b;
		}
	}

	public static byte[] hex2bin(String input) {
		return Hex.decode(input);
	}

	public static String bin2hex(byte[] bin) {
		return new String(Hex.encode(bin));
	}

	public static int ceil(double input) {
		return (int) Math.ceil(input);
	}

	public static int strlen(String string) {
		return string.length();
	}

	public static String substr(String input, int start) {
		return substr(input, start, input.length());
	}

	public static String substr(String input, int start, int length) {
		int end = start + length;
		if (end > input.length()) {
			end = input.length();
		}
		return input.substring(start, end);
	}

	public static byte[] randomBytes(int length) {
		byte[] result = new byte[length];
		try {
			SecureRandom.getInstanceStrong().nextBytes(result);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
		return result;
	}

}
