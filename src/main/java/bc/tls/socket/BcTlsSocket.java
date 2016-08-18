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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsPeer;
import org.bouncycastle.crypto.tls.TlsProtocol;
import org.bouncycastle.crypto.tls.TlsServer;
import org.bouncycastle.crypto.tls.TlsServerProtocol;

import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;

/**
 * BC Socket implementation
 * 
 * @author super-horst
 */
public class BcTlsSocket extends AbstractBcTlsSocket {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("Socket");

	private boolean isConnected = false;

	private boolean clientMode;
	private ClientAuthMode clientAuthMode;

	private boolean enableSessionCreation = true;

	private final Set<HandshakeCompletedListener> handshakeListener = new HashSet<HandshakeCompletedListener>();

	private String[] supportedCipherSuites = new String[0];
	private String[] enabledCipherSuites = new String[0];

	private String[] supportedProtocols = new String[0];
	private String[] enabledProtocols = new String[0];

	private TlsProtocol protocol;
	private TlsPeer peer;
	private SSLSession session;

	private final SecureRandom secureRandom;
	private final TlsAuthentication tlsAuth;
	private final TlsCredentials tlsCred;

	/**
	 * 
	 * @param s
	 *            the underlying network socket
	 * @param autoClose
	 *            close the underlying socket automatically
	 * @param random
	 *            a {@link SecureRandom} implementation
	 * @param authentication
	 *            tls authentication
	 */
	public BcTlsSocket(Socket s, boolean autoClose, SecureRandom random, TlsAuthentication authentication) {
		super(s, autoClose);
		this.secureRandom = random;
		this.tlsAuth = authentication;
		this.tlsCred = null;
	}

	/**
	 * 
	 * @param s
	 *            the underlying network socket
	 * @param autoClose
	 *            close the underlying socket automatically
	 * @param random
	 *            a {@link SecureRandom} implementation
	 * @param credentials
	 *            tls credentials
	 */
	public BcTlsSocket(Socket s, boolean autoClose, SecureRandom random, TlsCredentials credentials) {
		super(s, autoClose);
		this.secureRandom = random;
		this.tlsAuth = null;
		this.tlsCred = credentials;
	}

	@Override
	public synchronized void close() throws IOException {
		if (isClosed()) {
			return;
		}
		if (this.protocol != null && !this.protocol.isClosed()) {
			LOG.debug("Closing tls protocol");
			this.protocol.close();
		}
		super.close();
	}

	@Override
	public boolean isConnected() {
		return this.isConnected;
	}

	public void setSupportedCipherSuites(String[] suites) {
		if (suites == null) {
			this.supportedCipherSuites = new String[0];
		} else {
			this.supportedCipherSuites = suites.clone();
		}
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return supportedCipherSuites.clone();
	}

	public void setEnabledCipherSuites(String[] suites) {
		if (suites == null) {
			this.enabledCipherSuites = new String[0];
		} else {
			this.enabledCipherSuites = suites.clone();
		}
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites.clone();
	}

	public void setSupportedProtocols(String[] protocols) {
		if (protocols == null) {
			this.supportedProtocols = new String[0];
		} else {
			this.supportedProtocols = protocols.clone();
		}
	}

	@Override
	public String[] getSupportedProtocols() {
		return this.supportedProtocols;
	}

	@Override
	public String[] getEnabledProtocols() {
		return enabledProtocols.clone();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		this.enabledProtocols = protocols.clone();
	}

	@Override
	public SSLSession getSession() {
		if (session == null) {
			try {
				startHandshake();
			} catch (IOException e) {
				throw new IllegalStateException("Error performing handshake", e);
			}
		}
		return session;
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
		this.handshakeListener.add(listener);
	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
		this.handshakeListener.remove(listener);
	}

	@Override
	public void startHandshake() throws IOException {
		String hostname = socket.getInetAddress().getCanonicalHostName();
		if (this.clientMode) {
			LOG.debug("Performing handshake in client mode");
			this.protocol = new TlsClientProtocol(this.socket.getInputStream(), this.socket.getOutputStream(),
					this.secureRandom);
			this.peer = new BcTlsClient(this.tlsAuth, this.enabledCipherSuites, hostname);
			((TlsClientProtocol) this.protocol).connect((TlsClient) this.peer);
		} else {
			LOG.debug("Performing handshake in server mode");
			this.protocol = new TlsServerProtocol(this.socket.getInputStream(), this.socket.getOutputStream(),
					this.secureRandom);
			this.peer = new BcTlsServer(this.tlsCred, this.enabledCipherSuites, hostname);
			((TlsServerProtocol) this.protocol).accept((TlsServer) this.peer);
		}
		isConnected = true;
		
		LOG.info(String.format("Handshake successful, connected to %s", hostname));
		
		session = new BcTlsSession(this, peer);
	}

	@Override
	public InputStream getInputStream() {
		return this.protocol.getInputStream();
	}

	@Override
	public OutputStream getOutputStream() {
		return this.protocol.getOutputStream();
	}

	@Override
	public void setUseClientMode(boolean mode) {
		this.clientMode = mode;
	}

	@Override
	public boolean getUseClientMode() {
		return this.clientMode;
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		if (need) {
			this.clientAuthMode = ClientAuthMode.NEEDS;
		} else {
			this.clientAuthMode = ClientAuthMode.NONE;
		}
	}

	@Override
	public boolean getNeedClientAuth() {
		return this.clientAuthMode == ClientAuthMode.NEEDS;
	}

	@Override
	public void setWantClientAuth(boolean want) {
		if (want) {
			this.clientAuthMode = ClientAuthMode.WANTS;
		} else {
			this.clientAuthMode = ClientAuthMode.NONE;
		}
	}

	@Override
	public boolean getWantClientAuth() {
		return this.clientAuthMode == ClientAuthMode.WANTS;
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		this.enableSessionCreation = flag;
	}

	@Override
	public boolean getEnableSessionCreation() {
		return this.enableSessionCreation;
	}

}
