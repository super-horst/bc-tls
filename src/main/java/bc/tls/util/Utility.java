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
package bc.tls.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.x509.util.StreamParsingException;

public class Utility {
	
	public static X509Certificate loadX509Certificate(File cert) throws IOException {
		return loadX509Certificate(new FileInputStream(cert));
	}
	
	public static X509Certificate loadX509Certificate(byte[] cert) throws IOException {
		return loadX509Certificate(new ByteArrayInputStream(cert));
	}
	
	public static X509Certificate loadX509Certificate(InputStream in) throws IOException {
		X509CertParser parser = new X509CertParser();
		parser.engineInit(in);
		try {
			return (X509Certificate)parser.engineRead();
		} catch (StreamParsingException e) {
			throw new IOException(e);
		} finally {
			in.close();
		}
		
	}
	

}
