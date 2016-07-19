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
package bc.tls.socket;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;

import bc.tls.trust.NaiveX509TrustManager;
import bc.tls.util.Utility;

public class BcTlsAuthentication implements TlsAuthentication {

	final Set<Short> clientCertTypes = new HashSet<Short>(Arrays.asList(new Short[] {
			ClientCertificateType.ecdsa_fixed_ecdh,
			ClientCertificateType.rsa_fixed_ecdh,
			ClientCertificateType.rsa_fixed_dh,
			ClientCertificateType.dss_fixed_dh,
			ClientCertificateType.ecdsa_sign,
			ClientCertificateType.rsa_sign,
			ClientCertificateType.dss_sign }));

	/**
	 * Stores the tls server certificate chain
	 */
	private List<X509Certificate> serverCerts;

	private final X509TrustManager manager;
	private final TlsCredentials credentials;

	public BcTlsAuthentication() {
		manager = new NaiveX509TrustManager();
		credentials = null;
	}

	public BcTlsAuthentication(X509TrustManager trustManager, TlsCredentials tlsCredentials) {
		this.manager = trustManager;
		this.credentials = tlsCredentials;
	}

	@Override
	public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
		if (this.serverCerts == null) {
			final org.bouncycastle.asn1.x509.Certificate[] serverCertList = serverCertificate.getCertificateList();
			if (serverCertList != null) {
				try {
					this.serverCerts = new ArrayList<X509Certificate>();

					for (final org.bouncycastle.asn1.x509.Certificate cert : serverCertList) {
						this.serverCerts.add(Utility.loadX509Certificate(cert.getEncoded()));
					}
					// TODO find authType somehow
					this.manager.checkServerTrusted(
							this.serverCerts.toArray(new X509Certificate[this.serverCerts.size()]), "dummy");
				} catch (CertificateException e) {
					throw new IOException(e);
				}
			}
		}
	}

	@Override
	public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
		return credentials;
	}

	public List<X509Certificate> getServerCerts() {
		return serverCerts;
	}
}
