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

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import bc.tls.BcSecurityPrototype;
import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;

/**
 * BC-tls SSLContextSpi implementation
 * 
 * @author super-horst
 *
 */
public class BcTlsContextSpi extends SSLContextSpi {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("ContextSpi");

	private boolean isInitialised;

	private SSLParameters params;

	private KeyManager[] keyManager;
	private TrustManager[] trustManager;
	private SecureRandom random;
	BcSecurityPrototype securityPrototype;

	@Override
	protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
		if (isInitialised) {
			throw new IllegalStateException("Context is already initialised");
		}
		LOG.info("Initialising context");

		this.keyManager = km;
		this.trustManager = tm; // this should be X509TrustManager
								// -> no it shouldn't!!
		this.random = sr;
	}

	@Override
	protected SSLSocketFactory engineGetSocketFactory() {
		return new BcTlsSocketFactory(this.securityPrototype);
	}

	@Override
	protected SSLServerSocketFactory engineGetServerSocketFactory() {
		return new BcTlsServerSocketFactory(this.securityPrototype);
	}

	@Override
	protected SSLSessionContext engineGetServerSessionContext() {
		throw new UnsupportedOperationException("Not implemented");
	}

	@Override
	protected SSLSessionContext engineGetClientSessionContext() {
		throw new UnsupportedOperationException("Not implemented");
	}

	@Override
	protected SSLParameters engineGetDefaultSSLParameters() {
		return params;
	}

	@Override
	protected SSLEngine engineCreateSSLEngine() {
		throw new AbstractMethodError("Not implemented");
	}

	@Override
	protected SSLEngine engineCreateSSLEngine(String host, int port) {
		throw new AbstractMethodError("Not implemented");
	}

}
