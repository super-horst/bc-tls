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

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.crypto.tls.Certificate;

/**
 * Interface to generate valid TLS certificate chains from an unordered bunch of
 * {@link X509Certificate}.
 * 
 * @author super-horst
 * 
 * @see {@link Certificate}
 *
 */
public interface CertChainGenerator {

	/**
	 * Initialise the generator with a bunch of certificates forming a chain.
	 * The given certificates may represent multiple certificate chains, as long
	 * there is no link missing.
	 * 
	 * @param certificates
	 *            certificates used to generate chains
	 */
	void init(Collection<X509Certificate> certificates);

	/**
	 * Generate certificate chains from the given certificates.
	 * 
	 * @return a bunch of certificate chains
	 */
	Collection<Certificate> generateChains();

}
