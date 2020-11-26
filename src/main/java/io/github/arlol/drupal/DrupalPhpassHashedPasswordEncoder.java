package io.github.arlol.drupal;

import static io.github.arlol.drupal.PHP.ceil;
import static io.github.arlol.drupal.PHP.concat;
import static io.github.arlol.drupal.PHP.hash;
import static io.github.arlol.drupal.PHP.md5;
import static io.github.arlol.drupal.PHP.ord;
import static io.github.arlol.drupal.PHP.randomBytes;
import static io.github.arlol.drupal.PHP.strlen;
import static io.github.arlol.drupal.PHP.substr;
import static java.nio.charset.StandardCharsets.UTF_8;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * This is adapted from lib/Drupal/Core/Password/PhpassHashedPassword.php.
 * 
 * Variables: removed leading $ and changed to camelCase
 * 
 * Documentation was copied and adapted.
 * 
 * Standard functions were re-implemented in the Php class.
 * 
 * Secure password hashing functions based on the Portable PHP password hashing
 * framework.
 *
 * @see http://www.openwall.com/phpass/
 */
public class DrupalPhpassHashedPasswordEncoder implements PasswordEncoder {

	/**
	 * Maximum password length.
	 */
	private static final int PASSWORD_MAX_LENGTH = 512;

	/**
	 * The minimum allowed log2 number of iterations for password stretching.
	 */
	private static final int MIN_HASH_COUNT = 7;

	/**
	 * The maximum allowed log2 number of iterations for password stretching.
	 */
	private static final int MAX_HASH_COUNT = 30;

	/**
	 * The expected (and maximum) number of characters in a hashed password.
	 */
	private static final int HASH_LENGTH = 55;

	/**
	 * Returns a string for mapping an int to the corresponding base 64
	 * character.
	 */
	public static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	private static final char[] ITOA64_CHARS = ITOA64.toCharArray();

	/**
	 * PHP can return different data types. To reduce the changes to the
	 * converted code we fake the FALSE boolean with a null string. It has the
	 * same effect since anyString.equals(null) is false.
	 */
	private static final String FALSE = null;

	private int countLog2;

	public DrupalPhpassHashedPasswordEncoder(int countLog2) {
		this.countLog2 = this.enforceLog2Boundaries(countLog2);
	}

	@Override
	// This is adapted from the hash method
	public String encode(CharSequence password) {
		return crypt("SHA-512", password, generateSalt());
	}

	@Override
	// This is adapted from the check method
	public boolean matches(CharSequence password, String hash) {
		String storedHash;
		if (substr(hash, 0, 2) == "U$") {
			// This may be an updated password from user_update_7000(). Such
			// hashes have 'U' added as the first character and need an extra
			// md5() (see the Drupal 7 documentation).
			storedHash = substr(hash, 1);
			password = md5(password);
		} else {
			storedHash = hash;
		}

		String computedHash;

		String type = substr(storedHash, 0, 3);
		switch (type) {
		case "$S$":
			// A normal Drupal 7 password using sha512.
			computedHash = crypt("SHA-512", password, storedHash);
			break;

		case "$H$":
			// phpBB3 uses "$H$" for the same thing as "$P$".
		case "$P$":
			// A phpass password generated using md5. This is an
			// imported password or from an earlier Drupal version.
			computedHash = crypt("md5", password, storedHash);
			break;

		default:
			throw new IllegalArgumentException("Unsupported stuff");
		}

		return storedHash.equals(computedHash);
	}

	@Override
	// This is adapted from the needs_rehash method
	public boolean upgradeEncoding(String hash) {
		// Check whether this was an updated password.
		if (!substr(hash, 0, 3).equals("$S$") || strlen(hash) != HASH_LENGTH) {
			return true;
		}
		// Ensure that countLog2 is within set bounds.
		int countLog2 = enforceLog2Boundaries(this.countLog2);
		// Check whether the iteration count used differs from the standard
		// number.
		return getCountLog2(hash) != countLog2;
	}

	/**
	 * Encodes bytes into printable base 64 using the *nix standard from
	 * crypt().
	 *
	 * @param input The string containing bytes to encode.
	 * @param count The number of characters (bytes) to encode.
	 *
	 * @return Encoded string.
	 */
	protected String base64Encode(byte[] input, int count) {
		StringBuilder output = new StringBuilder();
		int i = 0;
		do {
			int value = ord(input[i++]);
			output.append(ITOA64_CHARS[value & 0x3f]);
			if (i < count) {
				value |= ord(input[i]) << 8;
			}
			output.append(ITOA64_CHARS[value >> 6 & 0x3f]);
			if (i++ >= count) {
				break;
			}
			if (i < count) {
				value |= ord(input[i]) << 16;
			}
			output.append(ITOA64_CHARS[value >> 12 & 0x3f]);
			if (i++ >= count) {
				break;
			}
			output.append(ITOA64_CHARS[value >> 18 & 0x3f]);
		} while (i < count);

		return output.toString();
	}

	/**
	 * Generates a random base 64-encoded salt prefixed with hash settings.
	 *
	 * Proper use of salts may defeat a number of attacks, including: - The
	 * ability to try candidate passwords against multiple hashes at once. - The
	 * ability to use pre-hashed lists of candidate passwords. - The ability to
	 * determine whether two users have the same (or different) password without
	 * actually having to guess one of the passwords.
	 *
	 * @return string A 12 character string containing the iteration count and a
	 *         random salt.
	 */
	protected String generateSalt() {
		String output = "$S$";
		// We encode the final log2 iteration count in base 64.
		output += ITOA64_CHARS[this.countLog2];
		// 6 bytes is the standard salt for a portable phpass hash.
		output += base64Encode(randomBytes(6), 6);
		return output;
	}

	/**
	 * Ensures that countLog2 is within set bounds.
	 *
	 * @param countLog2 Integer that determines the number of iterations used in
	 *                  the hashing process. A larger value is more secure, but
	 *                  takes more time to complete.
	 *
	 * @return Integer within set bounds that is closest to countLog2.
	 */
	protected int enforceLog2Boundaries(int countLog2) {
		if (countLog2 < MIN_HASH_COUNT) {
			return MIN_HASH_COUNT;
		} else if (countLog2 > MAX_HASH_COUNT) {
			return MAX_HASH_COUNT;
		}
		return countLog2;
	}

	/**
	 * Hash a password using a secure stretched hash.
	 *
	 * By using a salt and repeated hashing the password is "stretched". Its
	 * security is increased because it becomes much more computationally costly
	 * for an attacker to try to break the hash by brute-force computation of
	 * the hashes of a large number of plain-text words or strings to find a
	 * match.
	 *
	 * @param algo     The string name of a hashing algorithm usable by hash(),
	 *                 like 'sha256'.
	 * @param password Plain-text password up to 512 bytes (128 to 512 UTF-8
	 *                 characters) to hash.
	 * @param setting  An existing hash or the output of generateSalt(). Must be
	 *                 at least 12 characters (the settings and salt).
	 *
	 * @return A string containing the hashed password (and salt) or FALSE on
	 *         failure. The return string will be truncated at HASH_LENGTH
	 *         characters max.
	 */
	public String crypt(String algo, CharSequence password, String setting) {
		// Prevent DoS attacks by refusing to hash large passwords.
		if (password.length() > PASSWORD_MAX_LENGTH) {
			return FALSE;
		}

		// The first 12 characters of an existing hash are its setting string
		setting = substr(setting, 0, 12);

		if (setting.charAt(0) != '$' || setting.charAt(2) != '$') {
			return FALSE;
		}

		int countLog2 = getCountLog2(setting);

		String salt = substr(setting, 4, 8);
		// Hashes must have an 8 character salt.
		if (strlen(salt) != 8) {
			return FALSE;
		}

		if (countLog2 != enforceLog2Boundaries(countLog2)) {
			return FALSE;
		}

		// Convert the base 2 logarithm into an integer.
		int count = 1 << countLog2;

		byte[] hash = hash(algo, concat(salt, password));
		do {
			hash = hash(algo, concat(hash, password));
			count--;
		} while (count > 0);

		int len = new String(hash, UTF_8).length();

		String output = setting + base64Encode(hash, len);
		// base64Encode() of a 16 byte MD5 will always be 22 characters.
		// base64Encode() of a 64 byte sha512 will always be 86
		// characters.
		int expected = 12 + ceil(8D * len / 6);
		return strlen(output) == expected ? substr(output, 0, HASH_LENGTH)
				: FALSE;
	}

	/**
	 * Parses the log2 iteration count from a stored hash or setting string.
	 *
	 * @param setting An existing hash or the output of generateSalt(). Must be
	 *                at least 12 characters (the settings and salt).
	 *
	 * @return The log2 iteration count.
	 */
	public int getCountLog2(String setting) {
		return ITOA64.indexOf(setting.substring(3, 4));
	}

}
