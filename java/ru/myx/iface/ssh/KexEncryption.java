package ru.myx.iface.ssh;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

enum KexEncryption {
	/**
	 * 
	 */
	AES128_CBC("aes128-cbc", 16, 16) {
		@Override
		final Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
				throws GeneralSecurityException {
			final Cipher cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
			final SecretKeySpec secretKey = new SecretKeySpec( secret, "AES" );
			final IvParameterSpec hashKey = new IvParameterSpec( hash );
			cipher.init( mode, secretKey, hashKey );
			return cipher;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Cipher.getInstance( "AES/CBC/NoPadding" );
		}
	},
	/**
	 * 
	 */
	BLOWFISH_CBC("blowfish-cbc", 16, 8) {
		@Override
		final Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
				throws GeneralSecurityException {
			final Cipher cipher = Cipher.getInstance( "Blowfish/CBC/NoPadding" );
			final SecretKeySpec secretKey = new SecretKeySpec( secret, "Blowfish" );
			final IvParameterSpec hashKey = new IvParameterSpec( hash );
			cipher.init( mode, secretKey, hashKey );
			return cipher;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Cipher.getInstance( "Blowfish/CBC/NoPadding" );
		}
	},
	/**
	 * 
	 */
	AES256_CBC("aes256-cbc", 32, 16) {
		@Override
		final Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
				throws GeneralSecurityException {
			final Cipher cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
			final SecretKeySpec secretKey = new SecretKeySpec( secret, "AES" );
			final IvParameterSpec hashKey = new IvParameterSpec( hash );
			cipher.init( mode, secretKey, hashKey );
			return cipher;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Cipher.getInstance( "AES/CBC/NoPadding" );
		}
	},
	/**
	 * 
	 */
	AES192_CBC("aes192-cbc", 24, 16) {
		@Override
		final Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
				throws GeneralSecurityException {
			final Cipher cipher = Cipher.getInstance( "AES/CBC/NoPadding" );
			final SecretKeySpec secretKey = new SecretKeySpec( secret, "AES" );
			final IvParameterSpec hashKey = new IvParameterSpec( hash );
			cipher.init( mode, secretKey, hashKey );
			return cipher;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Cipher.getInstance( "AES/CBC/NoPadding" );
		}
	},
	/**
	 * 
	 */
	TDES_CBC("3des-cbc", 24, 8) {
		@Override
		final Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
				throws GeneralSecurityException {
			final Cipher cipher = Cipher.getInstance( "DESede/CBC/NoPadding" );
			final SecretKeySpec secretKey = new SecretKeySpec( secret, "AES" );
			final IvParameterSpec hashKey = new IvParameterSpec( hash );
			cipher.init( mode, secretKey, hashKey );
			return cipher;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			Cipher.getInstance( "DESede/CBC/NoPadding" );
		}
	},
	//
	;
	
	private final static Map<String, KexEncryption>	SUPPORTED_MAP;
	
	/**
	 * 
	 */
	public final static byte[]						KEX;
	static {
		final Map<String, KexEncryption> supportedMap = new HashMap<>();
		final StringBuilder supportedString = new StringBuilder();
		for (final KexEncryption current : KexEncryption.values()) {
			try {
				current.internCheckSupported();
				if (supportedString.length() > 0) {
					supportedString.append( ',' );
				}
				supportedString.append( current.name );
				supportedMap.put( current.name, current );
				Ssh.LOG.event( "SSH-KEX-ENC", "SUPPORTED", current.name );
			} catch (final GeneralSecurityException e) {
				Ssh.LOG.event( "SSH-KEX-ENC", "UNSUPPORTED", current.name );
			}
		}
		SUPPORTED_MAP = supportedMap;
		KEX = supportedString.toString().getBytes();
	}
	
	final static KexEncryption chooseKexEncryption(final String kexEncryptions) {
		for (final StringTokenizer st = new StringTokenizer( kexEncryptions, "," ); st.hasMoreTokens();) {
			final KexEncryption kexEncryption = KexEncryption.SUPPORTED_MAP.get( st.nextToken() );
			if (kexEncryption != null) {
				return kexEncryption;
			}
		}
		return null;
	}
	
	private final static byte[] limitLength(final byte[] bytes, final int length) {
		if (bytes.length > length) {
			final byte[] result = new byte[length];
			System.arraycopy( bytes, 0, result, 0, length );
			return result;
		}
		return bytes;
	}
	
	private final String	name;
	
	private final int		blockSize;
	
	private final int		ivSize;
	
	KexEncryption(final String name, final int blockSize, final int ivSize) {
		this.name = name;
		this.blockSize = blockSize;
		this.ivSize = ivSize;
	}
	
	final Cipher createCipher(final int mode, final byte[] secret, final byte[] hash) throws GeneralSecurityException {
		return this.createCipherImpl( mode,
				KexEncryption.limitLength( secret, this.blockSize ),
				KexEncryption.limitLength( hash, this.ivSize ) );
	}
	
	abstract Cipher createCipherImpl(final int mode, final byte[] secret, final byte[] hash)
			throws GeneralSecurityException;
	
	abstract void internCheckSupported() throws GeneralSecurityException;
}
