/*
 * Created on 28.04.2006
 */
package ru.myx.iface.ssh;

final class FlowConfiguration {
	final String	protocolName;
	
	final boolean	ignoreTargetPort;
	
	final boolean	ignoreGzip;
	
	final boolean	ignoreKeepAlive;
	
	final boolean	reverseProxied;
	
	FlowConfiguration(final String protocolName,
			final boolean ignoreTargetPort,
			final boolean ignoreGzip,
			final boolean ignoreKeepAlive,
			final boolean reverseProxied) {
		this.protocolName = protocolName;
		this.ignoreTargetPort = ignoreTargetPort;
		this.ignoreGzip = ignoreGzip;
		this.ignoreKeepAlive = ignoreKeepAlive;
		this.reverseProxied = reverseProxied;
	}
}
