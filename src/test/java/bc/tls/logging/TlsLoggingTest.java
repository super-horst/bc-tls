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


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TlsLoggingTest {

	@Before
	public void prepare() {
		LogConsumerFactory.setDefaultConsumer(null);
	}

	@Test
	public void consumerViaProperty() {
		String name = Log4JConsumer.class.getCanonicalName();
		System.setProperty(LogConsumerFactory.PROPERTY_KEY, name);

		LogConsumer logger = LogConsumerFactory.getDefaultConsumer();
		Assert.assertTrue(logger instanceof Log4JConsumer);
	}

	@Test
	public void consumerViaSetter() {
		LogConsumerFactory.setDefaultConsumer(new Log4JConsumer());

		LogConsumer logger = LogConsumerFactory.getDefaultConsumer();
		Assert.assertTrue(logger instanceof Log4JConsumer);
	}

	@Test
	public void consumerViaUnkownProperty() {
		System.setProperty(LogConsumerFactory.PROPERTY_KEY, "unkown.clazz.name");

		LogConsumer logger = LogConsumerFactory.getDefaultConsumer();
		Assert.assertTrue("Unexpected logger", logger instanceof NoOpLogConsumer);
	}

	@Test
	public void consumerViaNull() {
		LogConsumer logger = LogConsumerFactory.getDefaultConsumer();
		Assert.assertTrue(logger instanceof NoOpLogConsumer);
	}

}
