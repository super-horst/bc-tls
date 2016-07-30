package bc.tls.trust;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.crypto.tls.Certificate;

public class NaiveChainGenerator implements CertChainGenerator {

	private Collection<X509Certificate> certs;

	// map certs by SKI
	private Map<ByteHashKey, X509Certificate> mapped;

	@Override
	public void initialise(Collection<X509Certificate> certificates) {
		this.certs = Collections.unmodifiableCollection(certificates);
		this.mapped = new HashMap<ByteHashKey, X509Certificate>(certificates.size());

		for (X509Certificate certificate : certs) {
			SubjectKeyIdentifier subjKeyId = getSki(certificate);
			ByteHashKey key = new ByteHashKey(subjKeyId);
			mapped.put(key, certificate);
		}
	}

	@Override
	public Collection<Certificate> resolveToChain() {
		// mapping SKI to AKI
		Map<ByteHashKey, ByteHashKey> fragments = new HashMap<ByteHashKey, ByteHashKey>();

		for (X509Certificate certificate : certs) {
			if (isSelfSigned(certificate)) {
				continue;
			}
			ByteHashKey akiKey = new ByteHashKey(getAki(certificate));
			X509Certificate signingCert = mapped.get(akiKey);
			if (signingCert == null) {
				// no ca certificate in collection or ca certificate itself
				continue;
			}

			ByteHashKey skiKey = new ByteHashKey(getSki(certificate));
			fragments.put(skiKey, akiKey);
		}

		Set<ByteHashKey> allSkis = fragments.keySet();
		Set<ByteHashKey> allAkis = new HashSet<ByteHashKey>(fragments.values());
		// getting rid of everything that signed something, leaving only user
		// certificates
		allSkis.removeAll(allAkis);

		Collection<Certificate> chains = new HashSet<Certificate>(allSkis.size());
		for (ByteHashKey ski : allSkis) {
			chains.add(chain(ski));
		}

		return chains;
	}

	private Certificate chain(final ByteHashKey ski) {
		X509Certificate cert = this.mapped.get(ski);
		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		while (cert != null && !isSelfSigned(cert)) {
			chain.add(cert);
			cert = this.mapped.get(new ByteHashKey(getAki(cert)));
		}
		chain.add(cert);

		org.bouncycastle.asn1.x509.Certificate[] certChain = new org.bouncycastle.asn1.x509.Certificate[chain.size()];
		for (int i = 0; i < chain.size(); i++) {
			X509Certificate x509Cert = chain.get(i);
			try {
				certChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(x509Cert.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new IllegalStateException(e);
			}
		}

		return new Certificate(certChain);
	}

	private boolean isSelfSigned(X509Certificate certificate) {
		SubjectKeyIdentifier ski = getSki(certificate);
		AuthorityKeyIdentifier aki = getAki(certificate);
		if (aki == null) {
			// let's assume that self signed certificates have no use for an AKI
			return true;
		}
		return Arrays.equals(ski.getKeyIdentifier(), aki.getKeyIdentifier());
	}

	private SubjectKeyIdentifier getSki(X509Certificate cert) {
		byte[] ski = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
		if (ski == null)
			return null;

		return SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(ski).getOctets());
	}

	private AuthorityKeyIdentifier getAki(X509Certificate cert) {
		byte[] aki = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
		if (aki == null)
			return null;

		return AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(aki).getOctets());
	}

	private static class ByteHashKey {

		private final byte[] bytes;

		public ByteHashKey(SubjectKeyIdentifier ski) {
			this.bytes = ski.getKeyIdentifier();
		}

		public ByteHashKey(AuthorityKeyIdentifier aki) {
			this.bytes = aki.getKeyIdentifier();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ByteHashKey)) {
				return false;
			}
			return Arrays.equals(this.bytes, ((ByteHashKey) obj).bytes);
		}

		@Override
		public int hashCode() {
			return Arrays.hashCode(this.bytes);
		}
	}
}
