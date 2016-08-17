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
 * Factory to manage a default instance of a log consumer. If no default
 * consumer is set, a no-op will be handed out.
 * 
 * @author super-horst
 *
 */
public class LogConsumerFactory {

	/**
	 * Key for {@code System.setProperty(...)}
	 */
	static final String PROPERTY_KEY = "bc.tls.logging.consumer";

	private static volatile LogConsumer INSTANCE = null;

	public synchronized static LogConsumer getDefaultConsumer() {
		if (INSTANCE == null) {
			String clazz = System.getProperty(PROPERTY_KEY);
			if (clazz != null) {
				try {
					Class<?> cls = null;
					try {
						cls = Class.forName(clazz);
					} catch (ClassNotFoundException e) {
						ClassLoader cl = ClassLoader.getSystemClassLoader();
						if (cl != null) {
							cls = cl.loadClass(clazz);
						}
					}
					LogConsumer logger = (LogConsumer) cls.newInstance();
					INSTANCE = logger;
				} catch (Exception e) {
					e.printStackTrace();
					INSTANCE = new NoOpLogConsumer();
				}
			} else {
				INSTANCE = new NoOpLogConsumer();
			}
		}
		return INSTANCE;
	}

	public synchronized static void setDefaultConsumer(LogConsumer logger) {
		INSTANCE = logger;
	}

	public static LogConsumer getTaggedConsumer(String tag) {
		LogConsumer consumer = getDefaultConsumer();

		if (consumer instanceof NoOpLogConsumer) {
			// no point in tagging a no-op
			return consumer;
		}

		return new TaggedConsumer(consumer, tag);
	}
}
