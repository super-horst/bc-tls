/**
 * BouncyCastle TLS implementation
 * Copyright (C) 2016  super-horst
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 3 of the 
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */
package bc.tls;

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 * 
 * Contains some cipher suites and conversion functions to switch between
 * {@code String} and {@code Integer} representation.
 * <p>
 * Definition of cipher suites taken from
 * {@link org.bouncycastle.crypto.tls.CipherSuite}
 * 
 * @author super-horst
 */
public enum CipherSuite {
	TLS_RSA_WITH_NULL_MD5(0x0001),
	TLS_RSA_WITH_NULL_SHA(0x0002),
	TLS_RSA_WITH_RC4_128_MD5(0x0004),
	TLS_RSA_WITH_RC4_128_SHA(0x0005),
	TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000A),
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA(0x000D),
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA(0x0010),
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA(0x0013),
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016),

	/*
	 * Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are
	 * reserved to avoid collision with Fortezza-based cipher suites in SSL 3.
	 */

	/*
	 * RFC 3268
	 */
	TLS_RSA_WITH_AES_128_CBC_SHA(0x002F),
	TLS_DH_DSS_WITH_AES_128_CBC_SHA(0x0030),
	TLS_DH_RSA_WITH_AES_128_CBC_SHA(0x0031),
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA(0x0032),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
	TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
	TLS_DH_DSS_WITH_AES_256_CBC_SHA(0x0036),
	TLS_DH_RSA_WITH_AES_256_CBC_SHA(0x0037),
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA(0x0038),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),

	/*
	 * RFC 5932
	 */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041),
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0042),
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0043),
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA(0x0044),
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045),

	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084),
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0085),
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0086),
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA(0x0087),
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088),

	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BA),
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BB),
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BC),
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256(0x00BD),
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00BE),

	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C0),
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C1),
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C2),
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256(0x00C3),
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00C4),

	/*
	 * RFC 4162
	 */
	TLS_RSA_WITH_SEED_CBC_SHA(0x0096),
	TLS_DH_DSS_WITH_SEED_CBC_SHA(0x0097),
	TLS_DH_RSA_WITH_SEED_CBC_SHA(0x0098),
	TLS_DHE_DSS_WITH_SEED_CBC_SHA(0x0099),
	TLS_DHE_RSA_WITH_SEED_CBC_SHA(0x009A),

	/*
	 * RFC 4279
	 */
	TLS_PSK_WITH_RC4_128_SHA(0x008A),
	TLS_PSK_WITH_3DES_EDE_CBC_SHA(0x008B),
	TLS_PSK_WITH_AES_128_CBC_SHA(0x008C),
	TLS_PSK_WITH_AES_256_CBC_SHA(0x008D),
	TLS_DHE_PSK_WITH_RC4_128_SHA(0x008E),
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA(0x008F),
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA(0x0090),
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA(0x0091),
	TLS_RSA_PSK_WITH_RC4_128_SHA(0x0092),
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA(0x0093),
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA(0x0094),
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA(0x0095),

	/*
	 * RFC 4492
	 */
	TLS_ECDH_ECDSA_WITH_NULL_SHA(0xC001),
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA(0xC002),
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC003),
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA(0xC004),
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA(0xC005),
	TLS_ECDHE_ECDSA_WITH_NULL_SHA(0xC006),
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xC007),
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xC008),
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xC009),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xC00A),
	TLS_ECDH_RSA_WITH_NULL_SHA(0xC00B),
	TLS_ECDH_RSA_WITH_RC4_128_SHA(0xC00C),
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA(0xC00D),
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA(0xC00E),
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA(0xC00F),
	TLS_ECDHE_RSA_WITH_NULL_SHA(0xC010),
	TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xC011),
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xC012),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xC013),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xC014),
	TLS_ECDH_anon_WITH_NULL_SHA(0xC015),
	TLS_ECDH_anon_WITH_RC4_128_SHA(0xC016),
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA(0xC017),
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xC018),
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xC019),

	/*
	 * RFC 4785
	 */
	TLS_PSK_WITH_NULL_SHA(0x002C),
	TLS_DHE_PSK_WITH_NULL_SHA(0x002D),
	TLS_RSA_PSK_WITH_NULL_SHA(0x002E),

	/*
	 * RFC 5054
	 */
	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA(0xC01A),
	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA(0xC01B),
	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA(0xC01C),
	TLS_SRP_SHA_WITH_AES_128_CBC_SHA(0xC01D),
	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA(0xC01E),
	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA(0xC01F),
	TLS_SRP_SHA_WITH_AES_256_CBC_SHA(0xC020),
	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA(0xC021),
	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA(0xC022),

	/*
	 * RFC 5246
	 */
	TLS_RSA_WITH_NULL_SHA256(0x003B),
	TLS_RSA_WITH_AES_128_CBC_SHA256(0x003C),
	TLS_RSA_WITH_AES_256_CBC_SHA256(0x003D),
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256(0x003E),
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256(0x003F),
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256(0x0040),
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256(0x0068),
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256(0x0069),
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256(0x006A),
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006B),

	/*
	 * RFC 5288
	 */
	TLS_RSA_WITH_AES_128_GCM_SHA256(0x009C),
	TLS_RSA_WITH_AES_256_GCM_SHA384(0x009D),
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009E),
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009F),
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256(0x00A0),
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384(0x00A1),
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256(0x00A2),
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384(0x00A3),
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256(0x00A4),
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384(0x00A5),

	/*
	 * RFC 5289
	 */
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xC023),
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xC024),
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256(0xC025),
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384(0xC026),
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xC027),
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xC028),
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256(0xC029),
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384(0xC02A),
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xC02B),
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xC02C),
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256(0xC02D),
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384(0xC02E),
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xC02F),
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xC030),
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256(0xC031),
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384(0xC032),

	/*
	 * RFC 5487
	 */
	TLS_PSK_WITH_AES_128_GCM_SHA256(0x00A8),
	TLS_PSK_WITH_AES_256_GCM_SHA384(0x00A9),
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256(0x00AA),
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384(0x00AB),
	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256(0x00AC),
	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384(0x00AD),
	TLS_PSK_WITH_AES_128_CBC_SHA256(0x00AE),
	TLS_PSK_WITH_AES_256_CBC_SHA384(0x00AF),
	TLS_PSK_WITH_NULL_SHA256(0x00B0),
	TLS_PSK_WITH_NULL_SHA384(0x00B1),
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256(0x00B2),
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384(0x00B3),
	TLS_DHE_PSK_WITH_NULL_SHA256(0x00B4),
	TLS_DHE_PSK_WITH_NULL_SHA384(0x00B5),
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256(0x00B6),
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384(0x00B7),
	TLS_RSA_PSK_WITH_NULL_SHA256(0x00B8),
	TLS_RSA_PSK_WITH_NULL_SHA384(0x00B9),

	/*
	 * RFC 5489
	 */
	TLS_ECDHE_PSK_WITH_RC4_128_SHA(0xC033),
	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA(0xC034),
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA(0xC035),
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA(0xC036),
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(0xC037),
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384(0xC038),
	TLS_ECDHE_PSK_WITH_NULL_SHA(0xC039),
	TLS_ECDHE_PSK_WITH_NULL_SHA256(0xC03A),
	TLS_ECDHE_PSK_WITH_NULL_SHA384(0xC03B),

	/*
	 * RFC 6367
	 */
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC072),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC073),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256(0xC074),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384(0xC075),
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC076),
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC077),
	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256(0xC078),
	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384(0xC079),

	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07A),
	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07B),
	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07C),
	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07D),
	TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC07E),
	TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC07F),
	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC080),
	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC081),
	TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256(0xC082),
	TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384(0xC083),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC086),
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC087),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256(0xC088),
	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384(0xC089),
	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08A),
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08B),
	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256(0xC08C),
	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384(0xC08D),

	TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC08E),
	TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC08F),
	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC090),
	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC091),
	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256(0xC092),
	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384(0xC093),
	TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC094),
	TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC095),
	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC096),
	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC097),
	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC098),
	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC099),
	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256(0xC09A),
	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384(0xC09B),

	/*
	 * RFC 6655
	 */
	TLS_RSA_WITH_AES_128_CCM(0xC09C),
	TLS_RSA_WITH_AES_256_CCM(0xC09D),
	TLS_DHE_RSA_WITH_AES_128_CCM(0xC09E),
	TLS_DHE_RSA_WITH_AES_256_CCM(0xC09F),
	TLS_RSA_WITH_AES_128_CCM_8(0xC0A0),
	TLS_RSA_WITH_AES_256_CCM_8(0xC0A1),
	TLS_DHE_RSA_WITH_AES_128_CCM_8(0xC0A2),
	TLS_DHE_RSA_WITH_AES_256_CCM_8(0xC0A3),
	TLS_PSK_WITH_AES_128_CCM(0xC0A4),
	TLS_PSK_WITH_AES_256_CCM(0xC0A5),
	TLS_DHE_PSK_WITH_AES_128_CCM(0xC0A6),
	TLS_DHE_PSK_WITH_AES_256_CCM(0xC0A7),
	TLS_PSK_WITH_AES_128_CCM_8(0xC0A8),
	TLS_PSK_WITH_AES_256_CCM_8(0xC0A9),
	TLS_PSK_DHE_WITH_AES_128_CCM_8(0xC0AA),
	TLS_PSK_DHE_WITH_AES_256_CCM_8(0xC0AB),

	/*
	 * RFC 7251
	 */
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM(0xC0AC),
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM(0xC0AD),
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(0xC0AE),
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(0xC0AF),

	/*
	 * RFC 5746
	 */
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF),

	/*
	 * draft_ietf_tls_downgrade_scsv_00
	 */
	TLS_FALLBACK_SCSV(0x5600);

	private static final Map<Integer, CipherSuite> LOOKUP = new HashMap<Integer, CipherSuite>();

	private static final Map<Integer, Set<CipherSuite>> KEY_EXCHANGE_LOOKUP = new HashMap<Integer, Set<CipherSuite>>();

	private static final Map<Integer, Set<CipherSuite>> ENC_ALGO_LOOKUP = new HashMap<Integer, Set<CipherSuite>>();

	private static final Map<Short, Set<CipherSuite>> HASH_ALGO_LOOKUP = new HashMap<Short, Set<CipherSuite>>();

	/**
	 * Some good default I scraped up somewhere
	 * 
	 * @deprecated
	 */
	public static final String[] DEFAULT = convert(new CipherSuite[] {
			CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

			CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
			CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

			CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA });

	/**
	 * Build lookup table
	 */
	static {
		for (CipherSuite suite : CipherSuite.values()) {
			LOOKUP.put(suite.id, suite);
			{
				Set<CipherSuite> exchangeSuites = KEY_EXCHANGE_LOOKUP.get(suite.keyExchange);
				if (exchangeSuites == null) {
					exchangeSuites = EnumSet.<CipherSuite> noneOf(CipherSuite.class);
					KEY_EXCHANGE_LOOKUP.put(suite.keyExchange, exchangeSuites);
				}
				exchangeSuites.add(suite);
			}
			{
				Set<CipherSuite> cipherTypeSuites = ENC_ALGO_LOOKUP.get(suite.encryptionAlgo);
				if (cipherTypeSuites == null) {
					cipherTypeSuites = EnumSet.<CipherSuite> noneOf(CipherSuite.class);
					ENC_ALGO_LOOKUP.put(suite.encryptionAlgo, cipherTypeSuites);
				}
				cipherTypeSuites.add(suite);
			}
			{

				Set<CipherSuite> hashAlgoSuites = HASH_ALGO_LOOKUP.get(suite.hashAlgo);
				if (hashAlgoSuites == null) {
					hashAlgoSuites = EnumSet.<CipherSuite> noneOf(CipherSuite.class);
					HASH_ALGO_LOOKUP.put(suite.hashAlgo, hashAlgoSuites);
				}
				hashAlgoSuites.add(suite);
			}
		}
	}

	/**
	 * This suite's id
	 */
	private final Integer id;
	private Integer keyExchange;
	private Integer encryptionAlgo;
	private Short hashAlgo;

	private CipherSuite(Integer id) {
		this.id = id;
		try {
			this.keyExchange = TlsUtils.getKeyExchangeAlgorithm(this.id);
		} catch (IOException e) {
			this.keyExchange = null;
		}

		try {
			this.encryptionAlgo = TlsUtils.getEncryptionAlgorithm(this.id);
		} catch (IOException e) {
			this.encryptionAlgo = null;
		}

		String hashSpec = name().substring(name().lastIndexOf('_') + 1, name().length());
		if (hashSpec.contains("SHA")) {
			String shaLength = hashSpec.substring(hashSpec.length() - 3, hashSpec.length());
			if (shaLength.equals("SHA")) {
				this.hashAlgo = HashAlgorithm.sha1;
			} else if (shaLength.equals("256")) {
				this.hashAlgo = HashAlgorithm.sha256;
			} else if (shaLength.equals("384")) {
				this.hashAlgo = HashAlgorithm.sha384;
			} else if (shaLength.equals("512")) {
				this.hashAlgo = HashAlgorithm.sha512;
			}
		} else if (hashSpec.contains("MD5")) {
			this.hashAlgo = HashAlgorithm.md5;
		} else {
			this.hashAlgo = null;
		}

	}

	/**
	 * @return this cipher suite's id
	 */
	public Integer id() {
		return id;
	}

	/**
	 * @see {@link org.bouncycastle.crypto.tls.KeyExchangeAlgorithm}
	 * 
	 * @return this cipher suite's key exchange algorithm
	 */
	public int getKeyExchangeAlgorithm() {
		try {
			return TlsUtils.getKeyExchangeAlgorithm(this.id);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * @see {@link org.bouncycastle.crypto.tls.CipherType}
	 * 
	 * @return this cipher suite's cipher type
	 */
	public int getCipherType() {
		try {
			return TlsUtils.getCipherType(getKeyExchangeAlgorithm());
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * @see {@link org.bouncycastle.crypto.tls.EncryptionAlgorithm}
	 * 
	 * @return this cipher suite's encryption algorithm
	 */
	public int getEncryptionAlgorithm() {
		try {
			return TlsUtils.getEncryptionAlgorithm(this.id);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * @see {@link org.bouncycastle.crypto.tls.MACAlgorithm}
	 * 
	 * @return this cipher suite's MAC algorithm
	 */
	public int getMACAlgorithm() {
		try {
			return TlsUtils.getMACAlgorithm(this.id);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * @return this cipher suite's minimum TLS version
	 */
	public ProtocolVersion getMinimumVersion() {
		return TlsUtils.getMinimumVersion(this.id);
	}

	/**
	 * 
	 * @param suite
	 *            id value
	 * 
	 * @return the matching CipherSuite ... or {@code null} if the is no named
	 *         cipher suite with that id
	 */
	public static CipherSuite lookup(int suite) {
		return LOOKUP.get(suite);
	}

	public static Set<CipherSuite> lookupByKeyExchange(int keyExchange) {
		Set<CipherSuite> retVal = KEY_EXCHANGE_LOOKUP.get(keyExchange);
		if (retVal == null) {
			return Collections.<CipherSuite> emptySet();
		}
		return retVal;
	}

	public static Set<CipherSuite> lookupByEncryptionAlgorithm(int encAlgo) {
		Set<CipherSuite> retVal = ENC_ALGO_LOOKUP.get(encAlgo);
		if (retVal == null) {
			return Collections.<CipherSuite> emptySet();
		}
		return retVal;
	}

	public static Set<CipherSuite> lookupByHashAlgorithm(short hashAlgo) {
		Set<CipherSuite> retVal = HASH_ALGO_LOOKUP.get(hashAlgo);
		if (retVal == null) {
			return Collections.<CipherSuite> emptySet();
		}
		return retVal;
	}

	/**
	 * Converts a {@code CipherSuite[]} to a {@code String[]}
	 * 
	 * @param cipherSuites
	 *            the cipher suites
	 * @return the conversion result
	 */
	public static String[] convert(CipherSuite[] cipherSuites) {
		if (cipherSuites == null) {
			throw new IllegalArgumentException("Array to convert may not be null");
		}
		String[] suiteStrings = new String[cipherSuites.length];
		for (int i = 0; i < cipherSuites.length; i++) {
			suiteStrings[i] = cipherSuites[i].name();
		}
		return suiteStrings;
	}

	/**
	 * Converts a {@code int[]} to a {@code String[]}
	 * 
	 * @param suites
	 *            the cipher suites
	 * @return the conversion result
	 */
	public static String[] convert(int[] suites) {
		if (suites == null) {
			throw new IllegalArgumentException("Array to convert may not be null");
		}
		String[] suiteStrings = new String[suites.length];

		for (int i = 0; i < suites.length; i++) {
			CipherSuite suiteObj = LOOKUP.get(suites[i]);
			suiteStrings[i] = suiteObj.name();
		}
		return suiteStrings;
	}

	/**
	 * Converts a {@code String[]} to a {@code int[]}
	 * 
	 * @param suites
	 *            the cipher suites
	 * @return the conversion result
	 */
	public static int[] convert(String[] suites) {
		if (suites == null) {
			throw new IllegalArgumentException("Array to convert may not be null");
		}
		int[] suiteInts = new int[suites.length];

		for (int i = 0; i < suites.length; i++) {
			CipherSuite suiteObj = CipherSuite.valueOf(suites[i]);
			suiteInts[i] = suiteObj.id;
		}

		return suiteInts;
	}

}
