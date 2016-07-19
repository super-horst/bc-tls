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
import java.net.InetAddress;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsPeer;

import bc.tls.CipherSuite;

public class BcTlsSession implements SSLSession {

	private final TlsPeer tlsPeer;
	private final BcTlsSocket tlsSocket;

	public BcTlsSession(BcTlsSocket socket, TlsPeer peer) {
		this.tlsPeer = peer;
		this.tlsSocket = socket;
	}

	@Override
	public byte[] getId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SSLSessionContext getSessionContext() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getCreationTime() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public long getLastAccessedTime() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void invalidate() {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isValid() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void putValue(String name, Object value) {
		// TODO Auto-generated method stub

	}

	@Override
	public Object getValue(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removeValue(String name) {
		// TODO Auto-generated method stub

	}

	@Override
	public String[] getValueNames() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
		if (this.tlsPeer instanceof TlsClient) {
			final TlsAuthentication tlsAuth;
			try {
				tlsAuth = ((TlsClient) tlsPeer).getAuthentication();
			} catch (IOException e) {
				throw new SSLPeerUnverifiedException(e.toString());
			}

			if (tlsAuth == null || !(tlsAuth instanceof BcTlsAuthentication)) {
				throw new SSLPeerUnverifiedException("Peer provided no authentication");
			}
			final List<java.security.cert.X509Certificate> serverCerts = ((BcTlsAuthentication) tlsAuth)
					.getServerCerts();

			if (serverCerts != null && !serverCerts.isEmpty()) {
				return serverCerts.toArray(new Certificate[serverCerts.size()]);
			}
			throw new SSLPeerUnverifiedException("Peer cannot be identified, no server certificates reported.");
		}
		return null;
	}

	@Override
	public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
		final Certificate[] peerCerts = getPeerCertificates();

		final X509Certificate[] result = new X509Certificate[peerCerts.length];
		for (int i = 0; i < peerCerts.length; i++) {
			try {
				result[i] = X509Certificate.getInstance(peerCerts[i].getEncoded());
			} catch (CertificateEncodingException | CertificateException e) {
				throw new SSLPeerUnverifiedException(e.toString());
			}
		}
		return result;

	}

	@Override
	public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
		final X509Certificate[] peerCertChain = getPeerCertificateChain();

		return peerCertChain[0].getSubjectDN();
	}

	@Override
	public Certificate[] getLocalCertificates() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Principal getLocalPrincipal() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCipherSuite() {
		int cs = 0;
		if (this.tlsPeer instanceof BcTlsClient) {
			cs = ((BcTlsClient) this.tlsPeer).getSelectedCipherSuite();
		} else {
			return null;
		}
		return CipherSuite.lookup(cs).name();
	}

	@Override
	public String getProtocol() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getPeerHost() {
		InetAddress addr = tlsSocket.getInetAddress();
		if (addr == null) {
			addr = tlsSocket.getLocalAddress();
		}
		if (addr == null) {
			return null;
		}
		return addr.getHostName();
	}

	@Override
	public int getPeerPort() {
		int port = tlsSocket.getPort();
		if (port == -1) {
			port = tlsSocket.getLocalPort();
		}
		return port;
	}

	@Override
	public int getPacketBufferSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getApplicationBufferSize() {
		// TODO Auto-generated method stub
		return 0;
	}

}
