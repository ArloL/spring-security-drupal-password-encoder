package io.github.arlol.drupal;

import static io.github.arlol.drupal.PHP.bin2hex;
import static io.github.arlol.drupal.PHP.hash;
import static io.github.arlol.drupal.PHP.hex2bin;
import static io.github.arlol.drupal.PHP.md5;
import static io.github.arlol.drupal.PHP.ord;
import static io.github.arlol.drupal.PHP.strlen;
import static io.github.arlol.drupal.PHP.substr;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class PHPTest {

	String algo = "SHA-512";
	String salt = "VtYc19/L";
	CharSequence password = "alias chalice anybody scoff browbeat";
	byte[] passwordBytes = password.toString().getBytes(UTF_8);
	String concat = salt + password;

	@Test
	public void testMd5() throws Exception {
		assertEquals("5d41402abc4b2a76b9719d911017c592", md5("hello"));
	}

	@Test
	public void testMd5Hash() throws Exception {
		assertEquals(
				"5d41402abc4b2a76b9719d911017c592",
				bin2hex(hash("md5", "hello"))
		);
	}

	@Test
	public void testSaltPasswordHash() throws Exception {
		byte[] hash = PHP.hash(algo, salt + password);
		assertTrue(
				Arrays.equals(
						TestFiles.readAllBytes("saltPasswordHash.bin"),
						hash
				)
		);
		assertEquals(
				"97211053c60e2417cf61bb36605d164ffe71d8c97ac37847ce2be462af71fd64a8d828b9187bfe117bf231059210215841b5ff844df90edecfc7d96d0a10fdc9",
				bin2hex(hash)
		);
	}

	@Test
	public void testByteConcat() throws Exception {
		byte[] hash = hash(algo, salt + password);
		hash = ByteBuffer.allocate(hash.length + passwordBytes.length)
				.put(hash)
				.put(passwordBytes)
				.array();
		assertTrue(Arrays.equals(TestFiles.readAllBytes("concat.bin"), hash));

		hash = hash(algo, hash);
		assertEquals(
				"d7037aa88ddff81c66f195f12b56ec1bd7de484d688c84d33dc073d107ec8e12fa329095b0d6cacfe1f95dbb4361ac29d5c274624e3bb555e10bfc92a91f1649",
				bin2hex(hash)
		);
	}

	@Test
	public void testByteConcatHash() throws Exception {
		byte[] hash = hash(algo, salt + password);
		hash = hash(
				algo,
				ByteBuffer.allocate(hash.length + passwordBytes.length)
						.put(hash)
						.put(passwordBytes)
						.array()
		);
		assertEquals(
				"d7037aa88ddff81c66f195f12b56ec1bd7de484d688c84d33dc073d107ec8e12fa329095b0d6cacfe1f95dbb4361ac29d5c274624e3bb555e10bfc92a91f1649",
				bin2hex(hash)
		);
		assertTrue(Arrays.equals(TestFiles.readAllBytes("number2.bin"), hash));
	}

	@Test
	public void testHex2Bin() throws Exception {
		assertTrue(
				Arrays.equals(
						TestFiles.readAllBytes("hex2bin-1891.bin"),
						hex2bin("1891")
				)
		);
	}

	@Test
	public void testCeil() throws Exception {
		assertEquals(22, PHP.ceil(8D * 16 / 6));
		assertEquals(86, PHP.ceil(8D * 64 / 6));
	}

	@Test
	public void testOrd() throws Exception {
		assertEquals(0, ord(hex2bin("00")));
		assertEquals(1, ord(hex2bin("01")));
		assertEquals(85, ord(hex2bin("55")));
		assertEquals(145, ord(hex2bin("91")));
		assertEquals(170, ord(hex2bin("AA")));
		assertEquals(204, ord(hex2bin("CC")));
		assertEquals(255, ord(hex2bin("FF")));
	}

	@Test
	public void testSubstr() throws Exception {
		assertEquals("bcdef", substr("abcdef", 1));
		assertEquals("bcd", substr("abcdef", 1, 3));
		assertEquals("abcd", substr("abcdef", 0, 4));
		assertEquals("abcdef", substr("abcdef", 0, 8));
	}

	@Test
	public void testStrlen() {
		assertEquals(6, strlen("abcdef"));
		assertEquals(7, strlen(" ab cd "));
	}

}
