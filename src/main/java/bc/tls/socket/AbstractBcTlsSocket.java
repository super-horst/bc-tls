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
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLSocket;

import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;

/**
 * Abstract base class to handle the wrapped raw socket.
 * 
 * @author super-horst
 * 
 */
abstract class AbstractBcTlsSocket extends SSLSocket {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("RawSocket");

	private final Object closeLock = new Object();
	private final boolean autoClose;
	private boolean closed = false;

	protected final Socket socket;

	/**
	 * @param rawSocket
	 *            the socket to manage
	 * @param autoClose
	 *            whether to close to socket on close of parent
	 */
	AbstractBcTlsSocket(Socket rawSocket, boolean autoClose) {
		this.socket = rawSocket;
		this.autoClose = autoClose;
	}

	@Override
	public synchronized void close() throws IOException {
		synchronized (closeLock) {
			if (isClosed()) {
				return;
			}
			if (autoClose) {
				LOG.info("Closing socket");
				this.socket.close();
			}
			closed = true;
		}
	}

	@Override
	public boolean isClosed() {
		synchronized (closeLock) {
			return closed;
		}
	}

	@Override
	public InetAddress getInetAddress() {
		return this.socket.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {
		return this.socket.getLocalAddress();
	}

	@Override
	public int getPort() {
		return this.socket.getPort();
	}

	@Override
	public int getLocalPort() {
		return this.socket.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return this.socket.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return this.socket.getLocalSocketAddress();
	}

	@Override
	public SocketChannel getChannel() {
		// TODO implement!
		return null;
	}
}
