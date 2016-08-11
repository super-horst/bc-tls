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
package bc.tls.trust;

import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.tls.Certificate;

/**
 * Simplest certificate chain generator implementation.
 * <p>
 * Will resolve multiple chains from a given collection of
 * {@link X509Certificate} by looking up subject and issuer distinguished names.
 * <p>
 * Please be aware, that this algorithm will give you <b>all possible</b>
 * chains. Behaviour may include: The lower chain end being a Sub-CA certificate,
 * if there are no certificates signed with this certificate.
 * 
 * @author super-horst
 *
 */
public class NaiveChainGenerator implements CertChainGenerator {

	private Collection<X509Certificate> certs;

	// map certs by subject DN
	private Map<Principal, X509Certificate> mapped;

	@Override
	public void init(Collection<X509Certificate> certificates) {
		this.certs = Collections.unmodifiableCollection(certificates);
		this.mapped = new HashMap<Principal, X509Certificate>(certificates.size());

		for (X509Certificate certificate : certs) {
			mapped.put(certificate.getSubjectDN(), certificate);
		}
	}

	@Override
	public Collection<Certificate> generateChains() throws CertificateException {
		// mapping subject DN to issuer DN
		Map<Principal, Principal> fragments = new HashMap<Principal, Principal>();

		for (X509Certificate certificate : certs) {
			if (isSelfSigned(certificate)) {
				continue;
			}
			Principal issuer = certificate.getIssuerDN();
			X509Certificate signingCert = mapped.get(issuer);
			if (signingCert == null) {
				// no ca certificate in collection or ca certificate itself
				continue;
			}

			Principal subject = certificate.getSubjectDN();
			fragments.put(subject, issuer);
		}

		Set<Principal> allSubjects = fragments.keySet();
		Set<Principal> allIssuers = new HashSet<Principal>(fragments.values());
		// getting rid of everything that signed something, leaving only user
		// certificates
		allSubjects.removeAll(allIssuers);

		Collection<Certificate> chains = new HashSet<Certificate>(allSubjects.size());
		for (Principal subject : allSubjects) {
			chains.add(chain(subject));
		}

		return chains;
	}

	private Certificate chain(final Principal subject) throws CertificateException {
		X509Certificate cert = this.mapped.get(subject);
		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		while (cert != null && !isSelfSigned(cert)) {
			chain.add(cert);
			cert = this.mapped.get(cert.getIssuerDN());
		}
		if (cert != null) {
			chain.add(cert);
		} else {
			throw new CertificateException("Incomplete certificate chain given");
		}

		org.bouncycastle.asn1.x509.Certificate[] certChain = new org.bouncycastle.asn1.x509.Certificate[chain.size()];
		for (int i = 0; i < chain.size(); i++) {
			X509Certificate x509Cert = chain.get(i);
			try {
				certChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(x509Cert.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new CertificateException(e);
			}
		}

		return new Certificate(certChain);
	}

	private boolean isSelfSigned(X509Certificate certificate) {
		return certificate.getSubjectDN().equals(certificate.getIssuerDN());
	}
}
