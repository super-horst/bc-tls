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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

public class PooledX509TrustManager implements X509TrustManager {
	
	private final Set<X509Certificate> certPool;
	
	public PooledX509TrustManager(Collection<X509Certificate> certs) {
		this.certPool = new HashSet<X509Certificate>(certs);
	}
	
	public PooledX509TrustManager(X509Certificate[] certs) {
		this.certPool = new HashSet<X509Certificate>(Arrays.asList(certs));
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		isCertInPool(chain);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		isCertInPool(chain);
	}

	private void isCertInPool(X509Certificate[] chain) throws CertificateException {
		boolean pooled = false;
		for (X509Certificate cert : chain) {
			pooled |= this.certPool.contains(cert);
		}
		
		if (! pooled) {
			throw new CertificateException("Certificates were not found in pool");
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return certPool.toArray(new X509Certificate[certPool.size()]);
	}
}
