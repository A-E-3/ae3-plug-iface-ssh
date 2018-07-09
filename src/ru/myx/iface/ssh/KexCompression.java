package ru.myx.iface.ssh;

import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

enum KexCompression {
	/**
	 * 
	 */
	GZIP("gzip@myx.ru", false) {
	// ignore
	},
	/**
	 * 
	 */
	ZLIB("zlib", false) {
	// ignore
	},
	/**
	 * 
	 */
	NONE("none", true) {
	// ignore
	},
	//
	;
	
	private final static Map<String, KexCompression>	SUPPORTED_MAP;
	
	/**
	 * 
	 */
	public final static byte[]							KEX;
	static {
		final Map<String, KexCompression> supportedMap = new HashMap<>();
		final StringBuilder supportedString = new StringBuilder();
		for (final KexCompression current : KexCompression.values()) {
			if (!current.supported) {
				continue;
			}
			if (supportedString.length() > 0) {
				supportedString.append( ',' );
			}
			supportedString.append( current.name );
			supportedMap.put( current.name, current );
		}
		SUPPORTED_MAP = supportedMap;
		KEX = supportedString.toString().getBytes();
	}
	
	final static KexCompression chooseKexCompression(final String kexCompressions) {
		for (final StringTokenizer st = new StringTokenizer( kexCompressions, "," ); st.hasMoreTokens();) {
			final KexCompression kexCompression = KexCompression.SUPPORTED_MAP.get( st.nextToken() );
			if (kexCompression != null) {
				return kexCompression;
			}
		}
		return null;
	}
	
	private final String	name;
	
	private final boolean	supported;
	
	KexCompression(final String name, final boolean supported) {
		this.name = name;
		this.supported = supported;
	}
}
