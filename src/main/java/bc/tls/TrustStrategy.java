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

import java.util.Set;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;

public interface TrustStrategy {

	Set<Certificate> getTrustedCertificates();

	/**
	 * @return signature algorithms {@link SignatureAlgorithm}
	 */
	Set<Short> getSignatureAlgorithms();

	/**
	 * @return hash algorithms {@link HashAlgorithm}
	 */
	Set<Short> getHashAlgorithms();

	/**
	 * @return encryption algorithms {@link EncryptionAlgorithm}
	 */
	Set<Integer> getEncryptionAlgorithms();

	/**
	 * @return key exchange algorithms {@link KeyExchangeAlgorithm}
	 */
	Set<Integer> getKeyExchangeAlgorithms();
	
	
}
