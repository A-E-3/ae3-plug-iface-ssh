package ru.myx.iface.ssh;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

enum KexHostKey {
	/**
	 * 
	 */
	SSH_RSA("ssh-rsa") {
		private KeyPair	HOST_KEY_PAIR_RSA;
		
		private byte[]	HOST_KEY_SSH_RSA;
		
		private byte[]	SSH_TYPE_NAME;
		
		@Override
		final String getJceName() {
			return "RSA";
		}
		
		@Override
		final PrivateKey getPrivateKey() {
			return this.HOST_KEY_PAIR_RSA.getPrivate();
		}
		
		@Override
		final PublicKey getPublicKey() {
			return this.HOST_KEY_PAIR_RSA.getPublic();
		}
		
		@Override
		final byte[] getPublicSshKey() {
			return this.HOST_KEY_SSH_RSA;
		}
		
		@Override
		final byte[] getPublicSshType() {
			return this.SSH_TYPE_NAME;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			this.SSH_TYPE_NAME = this.getSshName().getBytes();
			{
				// Storage.getCreateRelativeFreeFolder( ...,
				// "settings/ssh/keys");
				final KeyPairGenerator generatorRSA = KeyPairGenerator.getInstance( "RSA" );
				generatorRSA.initialize( 2048 );
				this.HOST_KEY_PAIR_RSA = generatorRSA.generateKeyPair();
			}
			{
				final RSAPublicKey rsaHostKey = (RSAPublicKey) this.HOST_KEY_PAIR_RSA.getPublic();
				final byte[] sshRsaExponent = rsaHostKey.getPublicExponent().toByteArray();
				final byte[] sshRsaModulus = rsaHostKey.getModulus().toByteArray();
				final int sshRsaLength = 4
						+ this.SSH_TYPE_NAME.length
						+ 4
						+ sshRsaExponent.length
						+ 4
						+ sshRsaModulus.length;
				final byte[] temp = new byte[4 + sshRsaLength];
				int index = 0;
				index = Format.writeUint32( sshRsaLength, temp, index );
				index = Format.writeString( this.SSH_TYPE_NAME, temp, index );
				index = Format.writeString( sshRsaExponent, temp, index );
				index = Format.writeString( sshRsaModulus, temp, index );
				this.HOST_KEY_SSH_RSA = temp;
			}
		}
		
		@Override
		final boolean supports(final KexAlgorithm kex) {
			return true;
		}
	},
	/**
	 * 
	 */
	SSH_DSS("ssh-dss") {
		private KeyPair	HOST_KEY_PAIR_DSA;
		
		private byte[]	HOST_KEY_SSH_DSA;
		
		private byte[]	SSH_TYPE_NAME;
		
		@Override
		final String getJceName() {
			return "DSA";
		}
		
		@Override
		final PrivateKey getPrivateKey() {
			return this.HOST_KEY_PAIR_DSA.getPrivate();
		}
		
		@Override
		final PublicKey getPublicKey() {
			return this.HOST_KEY_PAIR_DSA.getPublic();
		}
		
		@Override
		final byte[] getPublicSshKey() {
			return this.HOST_KEY_SSH_DSA;
		}
		
		@Override
		final byte[] getPublicSshType() {
			return this.SSH_TYPE_NAME;
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			this.SSH_TYPE_NAME = this.getSshName().getBytes();
			{
				final KeyPairGenerator generatorDSA = KeyPairGenerator.getInstance( "DSA" );
				generatorDSA.initialize( 1024 );
				this.HOST_KEY_PAIR_DSA = generatorDSA.generateKeyPair();
			}
			{
				final DSAPublicKey dsaHostKey = (DSAPublicKey) this.HOST_KEY_PAIR_DSA.getPublic();
				final byte[] sshDsaP = dsaHostKey.getParams().getP().toByteArray();
				final byte[] sshDsaQ = dsaHostKey.getParams().getQ().toByteArray();
				final byte[] sshDsaG = dsaHostKey.getParams().getG().toByteArray();
				final byte[] sshDsaY = dsaHostKey.getY().toByteArray();
				final int sshRsaLength = 4
						+ this.SSH_TYPE_NAME.length
						+ 4
						+ sshDsaP.length
						+ 4
						+ sshDsaQ.length
						+ 4
						+ sshDsaG.length
						+ 4
						+ sshDsaY.length;
				final byte[] temp = new byte[4 + sshRsaLength];
				int index = 0;
				index = Format.writeUint32( sshRsaLength, temp, index );
				index = Format.writeString( this.SSH_TYPE_NAME, temp, index );
				index = Format.writeString( sshDsaP, temp, index );
				index = Format.writeString( sshDsaQ, temp, index );
				index = Format.writeString( sshDsaG, temp, index );
				index = Format.writeString( sshDsaY, temp, index );
				this.HOST_KEY_SSH_DSA = temp;
			}
		}
		
		@Override
		final boolean supports(final KexAlgorithm kex) {
			return kex.supportsDSA();
		}
		
	},
	//
	;
	
	private final static Map<String, KexHostKey>	SUPPORTED_MAP;
	
	/**
	 * 
	 */
	public final static byte[]						KEX;
	static {
		final Map<String, KexHostKey> supportedMap = new HashMap<>();
		final StringBuilder supportedString = new StringBuilder();
		for (final KexHostKey current : KexHostKey.values()) {
			try {
				current.internCheckSupported();
				if (supportedString.length() > 0) {
					supportedString.append( ',' );
				}
				supportedString.append( current.name );
				supportedMap.put( current.name, current );
				Ssh.LOG.event( "SSH-KEX-KEY", "SUPPORTED", current.name );
			} catch (final GeneralSecurityException e) {
				Ssh.LOG.event( "SSH-KEX-KEY", "UNSUPPORTED", current.name );
			}
		}
		SUPPORTED_MAP = supportedMap;
		KEX = supportedString.toString().getBytes();
	}
	
	final static KexHostKey chooseKexHostKey(final KexAlgorithm kex, final String kexHostKeys) {
		for (final StringTokenizer st = new StringTokenizer( kexHostKeys, "," ); st.hasMoreTokens();) {
			final KexHostKey kexHostKey = KexHostKey.SUPPORTED_MAP.get( st.nextToken() );
			if (kexHostKey != null) {
				if (kexHostKey.supports( kex )) {
					return kexHostKey;
				}
			}
		}
		return null;
	}
	
	private final String	name;
	
	KexHostKey(final String name) {
		this.name = name;
	}
	
	abstract String getJceName();
	
	abstract PrivateKey getPrivateKey();
	
	abstract PublicKey getPublicKey();
	
	abstract byte[] getPublicSshKey();
	
	abstract byte[] getPublicSshType();
	
	final String getSshName() {
		return this.name;
	}
	
	abstract void internCheckSupported() throws GeneralSecurityException;
	
	abstract boolean supports(final KexAlgorithm kex);
}
