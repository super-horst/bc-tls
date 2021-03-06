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
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.KeyExchangeAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.TlsUtils;

public class DefaultTrustStrategy implements TrustStrategy {

	private Set<Short> sigAlgos = new HashSet<Short>();
	private Set<Short> hashAlgos = new HashSet<Short>();
	private Set<Integer> encAlgos = new HashSet<Integer>();
	private Set<Integer> keyExAlgos = new HashSet<Integer>();
	
	private Set<Certificate> trustCerts = new HashSet<Certificate>();

	public DefaultTrustStrategy() {
		this.sigAlgos.add(SignatureAlgorithm.ecdsa);
		this.sigAlgos.add(SignatureAlgorithm.dsa);
		this.sigAlgos.add(SignatureAlgorithm.rsa);

		this.hashAlgos.add(HashAlgorithm.sha256);
		this.hashAlgos.add(HashAlgorithm.sha384);
		this.hashAlgos.add(HashAlgorithm.sha512);
		
		this.encAlgos.add(EncryptionAlgorithm.AES_128_GCM);
		this.encAlgos.add(EncryptionAlgorithm.AES_128_CBC);
		
		this.keyExAlgos.add(KeyExchangeAlgorithm.ECDHE_ECDSA);
		this.keyExAlgos.add(KeyExchangeAlgorithm.ECDHE_RSA);
		this.keyExAlgos.add(KeyExchangeAlgorithm.DHE_DSS);
		this.keyExAlgos.add(KeyExchangeAlgorithm.DHE_RSA);
		this.keyExAlgos.add(KeyExchangeAlgorithm.RSA);
	}

	public void addTrustedCertificates(Set<Certificate> trusted) {
		this.trustCerts.addAll(trusted);
	}
	
	@Override
	public Set<Certificate> getTrustedCertificates() {
		return Collections.unmodifiableSet(this.trustCerts);
	}

	@Override
	public Set<Short> getSignatureAlgorithms() {
		return Collections.unmodifiableSet(this.sigAlgos);
	}

	@Override
	public Set<Short> getHashAlgorithms() {
		return Collections.unmodifiableSet(this.hashAlgos);
	}

	@Override
	public Set<Integer> getEncryptionAlgorithms() {
		return Collections.unmodifiableSet(this.encAlgos);
	}

	@Override
	public Set<Integer> getKeyExchangeAlgorithms() {
		return Collections.unmodifiableSet(this.keyExAlgos);
	}

}
