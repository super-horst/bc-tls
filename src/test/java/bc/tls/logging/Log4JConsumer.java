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
package bc.tls.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4JConsumer implements LogConsumer {

	private static final Logger LOG = LogManager.getLogger();

	public Log4JConsumer() {
	}

	@Override
	public void trace(String message, Object... params) {
		LOG.trace(message, params);
		
	}

	@Override
	public void debug(String message, Object... params) {
		LOG.debug(message, params);
		
	}

	@Override
	public void info(String message, Object... params) {
		LOG.info(message, params);
		
	}

	@Override
	public void warn(String message, Object... params) {
		LOG.warn(message, params);
		
	}

	@Override
	public void error(String message, Object... params) {
		LOG.error(message, params);
	}

	@Override
	public void fatal(String message, Object... params) {
		LOG.fatal(message, params);
		
	}

}
