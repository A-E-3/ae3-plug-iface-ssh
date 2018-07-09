/*
 * Created on 19.04.2006
 */
package ru.myx.iface.ssh;

import java.util.function.Function;

final class KeepAliveReadConnector implements Function<SshSocketHandler, Object> {
	@Override
	public final Object apply(final SshSocketHandler parser) {
		parser.reconnect();
		return null;
	}
	
	@Override
	public final String toString() {
		return "KEEP-ALIVE RECONNECTOR";
	}
}
