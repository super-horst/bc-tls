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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import bc.tls.trust.BcTrustManager;
import bc.tls.trust.DefaultBcTrustManager;

public class BcTlsContextFactory {

	private final List<Certificate[]> chains = new ArrayList<Certificate[]>();
	private final Map<PublicKey, KeyPair> keyRing = new HashMap<PublicKey, KeyPair>();

	public void addKeyStore(KeyStore store, char[] password) throws KeyStoreException {
		Enumeration<String> aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			if (store.isKeyEntry(alias)) {
				try {
					Key privKey = store.getKey(alias, password);
					if (!(privKey instanceof PrivateKey)) {
						continue;
					}
					Certificate[] chain = store.getCertificateChain(alias);
					if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
						throw new KeyStoreException("Received empty chain for alias " + alias);
					}

					PublicKey pubKey = chain[0].getPublicKey();

					keyRing.put(pubKey, new KeyPair(pubKey, (PrivateKey) privKey));
					chains.add(chain);
				} catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
					throw new KeyStoreException(e);
				}
			}
		}
	}

	private BcTrustManager[] convertChains(TrustStrategy strategy) throws CertificateEncodingException, IOException {
		List<BcTrustManager> trustManager = new ArrayList<BcTrustManager>(this.chains.size());

		// remap keys to certificates here!

		for (Certificate[] chain : chains) {
			org.bouncycastle.asn1.x509.Certificate[] bcChain = new org.bouncycastle.asn1.x509.Certificate[chain.length];
			for (int i = 0; i < chain.length; i++) {
				byte[] certBytes = chain[i].getEncoded();
				bcChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(certBytes);
			}

			short type = resolveAlgos(bcChain);
			if (!strategy.getSignatureAlgorithms().contains(type)) {
				continue;
			}

			KeyPair pair = this.keyRing.get(chain[0].getPublicKey());
			AsymmetricKeyParameter pubKey = PublicKeyFactory.createKey(pair.getPublic().getEncoded());
			AsymmetricKeyParameter privKey = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
			AsymmetricCipherKeyPair bcPair = new AsymmetricCipherKeyPair(pubKey, privKey);

			trustManager.add(new DefaultBcTrustManager(bcPair, type, bcChain, strategy));
		}
		return trustManager.toArray(new BcTrustManager[trustManager.size()]);
	}

	/*
	 * have a look here:
	 * org.bouncycastle.crypto.tls.TlsUtils.getClientCertificateType(
	 * Certificate, Certificate)
	 */
	private short resolveAlgos(org.bouncycastle.asn1.x509.Certificate[] chain) throws IOException {
		AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(chain[0].getSubjectPublicKeyInfo());

		Short type = null;

		if (publicKey instanceof RSAKeyParameters) {
			type = SignatureAlgorithm.rsa;
		} else if (publicKey instanceof DSAPublicKeyParameters) {
			type = SignatureAlgorithm.dsa;
		} else if (publicKey instanceof ECPublicKeyParameters) {
			type = SignatureAlgorithm.ecdsa;
		}
		if (type == null) {
			throw new IOException("Unkown certificate type");
		} else if (!isSignatureCertificate(chain[0])) {
			throw new IOException("Invalid signature certificate");
		}
		return type;
	}

	/*
	 * have a look here:
	 * org.bouncycastle.crypto.tls.TlsUtils.validateKeyUsage(Certificate, int)
	 */
	private boolean isSignatureCertificate(org.bouncycastle.asn1.x509.Certificate c) {
		int sigUsageBits = KeyUsage.digitalSignature;
		Extensions exts = c.getTBSCertificate().getExtensions();
		if (exts != null) {
			KeyUsage ku = KeyUsage.fromExtensions(exts);
			if (ku != null) {
				int bits = ku.getBytes()[0] & 0xff;
				if ((bits & sigUsageBits) == sigUsageBits) {
					return true;
				}
			}
		}
		return false;
	}

	public BcTrustManager[] createTrustManager(TrustStrategy strategy)
			throws CertificateEncodingException, IOException {
		return convertChains(strategy);
	}

	public SSLContext createContext(TrustStrategy strategy) throws CertificateEncodingException, IOException {
		BcTrustManager[] trustManager = convertChains(strategy);

		return null;
	}

}
