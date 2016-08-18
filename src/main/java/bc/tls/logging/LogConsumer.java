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

/**
 * Interface for a log consumer. You may implement one fitting your logging
 * system. It can be set using the static methods in {@link LogConsumerFactory}.
 * 
 * @author super-horst
 *
 */
public interface LogConsumer {

	/**
	 * Log with trace level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void trace(String message, Object... params);

	/**
	 * Log with debug level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void debug(String message, Object... params);

	/**
	 * Log with info level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void info(String message, Object... params);

	/**
	 * Log with warn level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void warn(String message, Object... params);

	/**
	 * Log with error level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void error(String message, Object... params);

	/**
	 * Log with fatal level.
	 * 
	 * @param message
	 *            The log message
	 * @param params
	 *            Any number and type of objects
	 */
	void fatal(String message, Object... params);

	/**
	 * Check if a certain log level is enabled.
	 * 
	 * @param level
	 *            the level to check
	 * 
	 * @return whether it's enabled or not
	 */
	boolean isLevelEnabled(LogLevel level);
}
