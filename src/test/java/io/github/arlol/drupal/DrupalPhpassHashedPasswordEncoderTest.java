package io.github.arlol.drupal;

import static io.github.arlol.drupal.PHP.hex2bin;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;

public class DrupalPhpassHashedPasswordEncoderTest {

	DrupalPhpassHashedPasswordEncoder encoder = new DrupalPhpassHashedPasswordEncoder(
			11);

	@Test
	public void testEncodeAndMatches() throws Exception {
		String password = "alias chalice anybody scoff browbeat";
		String encodedPassword = encoder.encode(password);
		assertTrue(encoder.matches(password, encodedPassword));
		assertFalse(encoder.matches("wrong password", encodedPassword));
	}

	@Test
	public void testMatches() throws Exception {
		assertTrue(encoder.matches("alias chalice anybody scoff browbeat",
				"$S$EVtYc19/LM2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUK"));
		assertFalse(encoder.matches("wrong password",
				"$S$EVtYc19/LM2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUK"));
		assertTrue(encoder.matches("YXplcOBfVhe-aCDE",
				"$S$EMToK6OMiG6dNTFfZCLtiRKsit3yUR/TAQTJckBWm/Cn7RPcffCl"));
		assertFalse(encoder.matches("wrong password",
				"$S$EMToK6OMiG6dNTFfZCLtiRKsit3yUR/TAQTJckBWm/Cn7RPcffCl"));
	}

	@Test
	public void testBase64Encode() throws Exception {
		assertEquals("k.", encoder.base64Encode("0".getBytes(UTF_8), 1));
		assertEquals("k2XAnEHBqQ1Ct.",
				encoder.base64Encode("0123456789".getBytes(UTF_8), 10));
		assertEquals("V7qMYJaNbVKOehKPgtqPk3bQnFLRqR5Std5",
				encoder.base64Encode(
						"abcdefghijkmlnopqrstuvwxyz".getBytes(UTF_8),
						26));

		byte[] hex2bin91 = hex2bin("91");
		assertEquals("F0", encoder.base64Encode(hex2bin91, 1));
		byte[] decode = Hex.decode(
				"1891e20e884e977a08e94806ffb2af14d2520cabfe4c5c6c657bf2e256093d68f5acab45519c32175d746f779f43a2298f337495945be1fb1a2d846cd9fd278c");
		assertEquals(
				"M2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUKxgiOFFldALo3RjRrb17O8DC1RJGtKVjj4hE6PNrz7A0",
				encoder.base64Encode(decode, 64));
	}

	@Test
	public void testPasswordCrypt() throws Exception {
		String crypt = encoder.crypt("SHA-512",
				"alias chalice anybody scoff browbeat",
				"$S$EVtYc19/LM2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUK");
		assertEquals("$S$EVtYc19/LM2dsCUcHLe50dXY/z9vfI6hIAgezAl3PZhbwWPJ0xUK",
				crypt);
	}

}
