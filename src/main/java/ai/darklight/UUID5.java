package ai.darklight;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.json.JSONObject;
import org.webpki.jcs.JsonCanonicalizer;

/**
 * This class contains static methods that leverage {@link java.util.UUID} and
 * {@link java.security.MessageDigest} to create version-5 UUIDs with full
 * namespace support.
 * 
 * <p>
 * This class was informed by <a href="http://www.ietf.org/rfc/rfc4122.txt">RFC
 * 4122</a>. Since RFC 4122 is vague on how a 160-bit hash is turned into the
 * 122 free bits of a UUID (6 bits being used for version and variant
 * information), this class was modelled after java.util.UUID's type-3
 * implementation and validated against the D language's phobos library
 * <a href="http://dlang.org/phobos/std_uuid.html">std.uuid</a>, which in turn
 * was modelled after the Boost project's
 * <a href="http://www.boost.org/doc/libs/1_42_0/libs/uuid/uuid.html"
 * >boost.uuid</a>; and also validated against the Python language's
 * <a href="http://docs.python.org/2/library/uuid.html">uuid</a> library.
 * 
 * A lot of this work was modeled after Luther Tychonievich's UUID5
 * implementation. Thank you!
 * 
 * @see java.util.UUID
 * @see java.security.MessageDigest
 * 
 * @author Ryan Joyce rjoyce@darklight.ai
 *
 */
public class UUID5 {
	
	static final int VARIANT = 2;
	static final int VERSION = 5;

	/**
	 * The variant number associated with this {@code UUID}. The variant number
	 * describes the layout of the {@code UUID}.
	 *
	 * The variant number has the following meaning:
	 * <ul>
	 * <li>0 Reserved for NCS backward compatibility
	 * <li>2
	 * <a href="http://www.ietf.org/rfc/rfc4122.txt">IETF&nbsp;RFC&nbsp;4122</a>
	 * (Leach-Salz), used by this class
	 * <li>6 Reserved, Microsoft Corporation backward compatibility
	 * <li>7 Reserved for future definition
	 * </ul>
	 *
	 * @return The variant number of this {@code UUID}
	 */
	public static Integer variant() {
		return VARIANT;
	}

	/**
	 * The version number associated with this {@code UUID}. The version number
	 * describes how this {@code UUID} was generated.
	 *
	 * The version number has the following meaning:
	 * <ul>
	 * <li>1 Time-based UUID
	 * <li>2 DCE security UUID
	 * <li>3 Name-based UUID (MD5)
	 * <li>4 Randomly generated UUID
	 * <li>5 Name-based UUID (SHA-1)
	 * </ul>
	 *
	 * @return The version number of this {@code UUID}
	 */
	public static Integer version() {
		return VERSION;
	}

	/**
	 * Hide the constructor
	 */
	private UUID5() {
	}

	/**
	 * 
	 * 
	 * @param namespace {@code String} representation of the UUID of the namespace
	 * @param material  {@code String} representation of the JSON node containing
	 *                  the material to be used for generating the identifier
	 * @param filter    {@code String} comma separated values representing the names
	 *                  of the specific properties to be used from the JSON node
	 *                  materials
	 * 
	 * @return The deterministic identifier in {@code String} form
	 */
	public static UUID generateDeterministicId(final UUID namespace, final String material, final String filter) {
		// Check that the material passed is a JSON Object
		JSONObject json = new JSONObject(material);

		// Only modify the JSON if a filter has been provided
		if (filter != null && !filter.isBlank()) {
			// Turn the filter into a list and extract the values from the materials
			List<String> filters = Arrays.asList(filter.split("\\s*,\\s*"));

			JSONObject filteredJson = new JSONObject();
			for (String key : filters) {
				filteredJson.put(key, json.get(key));
			}

			json = filteredJson;
		}
		
		// Return the canonicalized JSON data
		JsonCanonicalizer jsonCanonicalizer = null;
		try {
			jsonCanonicalizer = new JsonCanonicalizer(json.toString());
			return UUID5.fromUTF8(namespace, jsonCanonicalizer.getEncodedString());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Similar to UUID.nameUUIDFromBytes, but does version 5 (sha-1) not version 3
	 * (md5)
	 * 
	 * @param name The bytes to use as the "name" of this hash
	 * @return the UUID object
	 */
	public static UUID fromBytes(byte[] name) {
		if (name == null) {
			throw new NullPointerException("name == null");
		}
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			return makeUUID(md.digest(name), 5);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Similar to UUID.nameUUIDFromBytes, but does version 5 (sha-1) not version 3
	 * (md5) and uses a namespace
	 * 
	 * @param namespace The namespace to use for this UUID. If null, uses
	 *                  00000000-0000-0000-0000-000000000000
	 * @param name      The bytes to use as the "name" of this hash
	 * @return the UUID object
	 */
	public static UUID fromBytes(UUID namespace, byte[] name) {
		if (name == null) {
			throw new NullPointerException("name == null");
		}
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			if (namespace == null) {
				md.update(new byte[16]);
			} else {
				md.update(asBytes(namespace.getMostSignificantBits(), ByteOrder.BIG_ENDIAN));
				md.update(asBytes(namespace.getLeastSignificantBits(), ByteOrder.BIG_ENDIAN));
			}
			return makeUUID(md.digest(name), 5);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Similar to UUID.nameUUIDFromBytes, but does version 5 (sha-1) not version 3
	 * (md5)
	 * 
	 * @param name The string to be encoded in utf-8 to get the bytes to hash
	 * @return the UUID object
	 */
	public static UUID fromUTF8(String name) {
		return UUID5.fromBytes(name.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Similar to UUID.nameUUIDFromBytes, but does version 5 (sha-1) not version 3
	 * (md5) and uses a namespace
	 * 
	 * @param namespace The namespace to use for this UUID. If null, uses
	 *                  00000000-0000-0000-0000-000000000000
	 * @param name      The string to be encoded in utf-8 to get the bytes to hash
	 * @return the UUID object
	 */
	public static UUID fromUTF8(UUID namespace, String name) {
		return UUID5.fromBytes(namespace, name.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * A helper method for making uuid objects, which in java store longs not bytes
	 * 
	 * @param src    An array of bytes having at least offset+8 elements
	 * @param offset Where to start extracting a long
	 * @param order  either ByteOrder.BIG_ENDIAN or ByteOrder.LITTLE_ENDIAN
	 * @return a long, the specified endianness of which matches the bytes in
	 *         src[offset,offset+8]
	 */
	static long peekLong(final byte[] src, final int offset, final ByteOrder order) {
		long ans = 0;
		if (order == ByteOrder.BIG_ENDIAN) {
			for (int i = offset; i < offset + 8; i += 1) {
				ans <<= 8;
				ans |= src[i] & 0xffL;
			}
		} else {
			for (int i = offset + 7; i >= offset; i -= 1) {
				ans <<= 8;
				ans |= src[i] & 0xffL;
			}
		}
		return ans;
	}

	/**
	 * A helper method for writing uuid objects, which in java store longs not bytes
	 * 
	 * @param data   A long to write into the dest array
	 * @param dest   An array of bytes having at least offset+8 elements
	 * @param offset Where to start writing a long
	 * @param order  either ByteOrder.BIG_ENDIAN or ByteOrder.LITTLE_ENDIAN
	 */
	static void putLong(long data, final byte[] dest, final int offset, final ByteOrder order) {
		if (order == ByteOrder.BIG_ENDIAN) {
			for (int i = offset + 7; i >= offset; i -= 1) {
				dest[i] = (byte) (data & 0xff);
				data >>= 8;
			}
		} else {
			for (int i = offset; i < offset + 8; i += 1) {
				dest[i] = (byte) (data & 0xff);
				data >>= 8;
			}
		}
	}

	/**
	 * A helper method for reading uuid objects, which in java store longs not bytes
	 * 
	 * @param data  a long to convert to bytes
	 * @param order either ByteOrder.BIG_ENDIAN or ByteOrder.LITTLE_ENDIAN
	 * @return an array of 8 bytes
	 */
	static byte[] asBytes(long data, final ByteOrder order) {
		byte[] ans = new byte[8];
		putLong(data, ans, 0, order);
		return ans;
	}

	/**
	 * A private method from UUID pulled out here so we have access to it.
	 * 
	 * @param hash    A 16 (or more) byte array to be the basis of the UUID
	 * @param version The version number to replace 4 bits of the hash (the variant
	 *                code will replace 2 more bits))
	 * @return A UUID object
	 */
	static UUID makeUUID(byte[] hash, int version) {
		long msb = peekLong(hash, 0, ByteOrder.BIG_ENDIAN);
		long lsb = peekLong(hash, 8, ByteOrder.BIG_ENDIAN);

		// Set the version field
		msb &= ~(0xfL << 12);
		msb |= ((long) version) << 12;

		// Set the variant field to 2
		lsb &= ~(0x3L << 62);
		lsb |= 2L << 62;

		return new UUID(msb, lsb);
	}

}
