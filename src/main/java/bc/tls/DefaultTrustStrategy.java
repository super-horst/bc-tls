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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;

public class DefaultTrustStrategy implements TrustStrategy {

	private Set<Short> sigAlgos;
	private Set<Short> hashAlgos;

	public DefaultTrustStrategy() {
		this.sigAlgos = new HashSet<Short>();
		this.sigAlgos.add(SignatureAlgorithm.ecdsa);
		this.sigAlgos.add(SignatureAlgorithm.dsa);
		this.sigAlgos.add(SignatureAlgorithm.rsa);
		
		this.hashAlgos = new HashSet<Short>();
		this.sigAlgos.add(HashAlgorithm.sha256);
		this.sigAlgos.add(HashAlgorithm.sha384);
		this.sigAlgos.add(HashAlgorithm.sha512);
	}

	@Override
	public Set<Certificate> getTrustedCertificates() {

		return null;
	}

	@Override
	public Set<Short> getSignatureAlgorithms() {
		return Collections.unmodifiableSet(this.sigAlgos);
	}

	@Override
	public Set<Short> getHashAlgorithms() {
		return Collections.unmodifiableSet(this.hashAlgos);
	}

}
