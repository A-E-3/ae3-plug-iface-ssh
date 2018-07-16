package ru.myx.iface.ssh;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

enum KexMAC {
	/**
	 * 
	 */
	HMAC_MD5_96("hmac-md5-96") {
		@Override
		final Mac createMac(final byte[] key) throws GeneralSecurityException {
			final Mac mac = Mac.getInstance( "HmacMD5" );
			final SecretKeySpec secretKey = new SecretKeySpec( key, "HmacMD5" );
			mac.init( secretKey );
			return mac;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Mac.getInstance( "HmacMD5" );
		}
	},
	/**
	 * 
	 */
	HMAC_SHA1_96("hmac-sha1-96") {
		@Override
		final Mac createMac(final byte[] key) throws GeneralSecurityException {
			final Mac mac = Mac.getInstance( "HmacSHA1" );
			final SecretKeySpec secretKey = new SecretKeySpec( key, "HmacSHA1" );
			mac.init( secretKey );
			return mac;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Mac.getInstance( "HmacSHA1" );
		}
	},
	/**
	 * 
	 */
	HMAC_MD5("hmac-md5") {
		@Override
		final Mac createMac(final byte[] key) throws GeneralSecurityException {
			final Mac mac = Mac.getInstance( "HmacMD5" );
			final SecretKeySpec secretKey = new SecretKeySpec( key, "HmacMD5" );
			mac.init( secretKey );
			return mac;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Mac.getInstance( "HmacMD5" );
		}
	},
	/**
	 * 
	 */
	HMAC_SHA1("hmac-sha1") {
		@Override
		final Mac createMac(final byte[] key) throws GeneralSecurityException {
			final Mac mac = Mac.getInstance( "HmacSHA1" );
			final SecretKeySpec secretKey = new SecretKeySpec( key, "HmacSHA1" );
			mac.init( secretKey );
			return mac;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Mac.getInstance( "HmacSHA1" );
		}
	},
	/**
	 * 
	 */
	NONE("none") {
		@Override
		final Mac createMac(final byte[] key) {
			return null;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			// ignore
		}
	},
	//
	;
	
	private final static Map<String, KexMAC>	SUPPORTED_MAP;
	
	/**
	 * 
	 */
	public final static byte[]					KEX;
	static {
		final Map<String, KexMAC> supportedMap = new HashMap<>();
		final StringBuilder supportedString = new StringBuilder();
		for (final KexMAC current : KexMAC.values()) {
			try {
				current.internCheckSupported();
				if (supportedString.length() > 0) {
					supportedString.append( ',' );
				}
				supportedString.append( current.name );
				supportedMap.put( current.name, current );
				Ssh.LOG.event( "SSH-KEX-MAC", "SUPPORTED", current.name );
			} catch (final GeneralSecurityException e) {
				Ssh.LOG.event( "SSH-KEX-MAC", "UNSUPPORTED", current.name );
			}
		}
		SUPPORTED_MAP = supportedMap;
		KEX = supportedString.toString().getBytes();
	}
	
	final static KexMAC chooseKexMAC(final String kexMACs) {
		for (final StringTokenizer st = new StringTokenizer( kexMACs, "," ); st.hasMoreTokens();) {
			final KexMAC kexMAC = KexMAC.SUPPORTED_MAP.get( st.nextToken() );
			if (kexMAC != null) {
				return kexMAC;
			}
		}
		return null;
	}
	
	private final String	name;
	
	KexMAC(final String name) {
		this.name = name;
	}
	
	abstract Mac createMac(final byte[] key) throws GeneralSecurityException;
	
	abstract void internCheckSupported() throws GeneralSecurityException;
}
