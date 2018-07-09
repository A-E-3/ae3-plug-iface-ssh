package ru.myx.iface.ssh;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

enum KexAlgorithm {
	/**
	 * 
	 */
	DIFFIE_HELLMAN_GROUP_EXCHNAGE_SHA256("diffie-hellman-group-exchange-sha256") {
		
		private boolean	rsa	= true;
		
		private boolean	dsa	= true;
		
		@Override
		final AlgorithmImpl createInstance() throws NoSuchAlgorithmException {
			return new DiffieHellmanGroupExchangeAlgorithmImpl( MessageDigest.getInstance( "SHA-256" ) );
		}
		
		@Override
		final String getJceDigestName() {
			return "SHA256";
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			MessageDigest.getInstance( "SHA-256" );
			KeyFactory.getInstance( "DH" );
			KeyPairGenerator.getInstance( "DH" );
			KeyAgreement.getInstance( "DH" );
			try {
				Signature.getInstance( "SHA256withRSA" );
			} catch (final GeneralSecurityException e) {
				this.rsa = false;
			}
			try {
				Signature.getInstance( "SHA256withDSA" );
			} catch (final GeneralSecurityException e) {
				this.dsa = false;
			}
			if (!(this.rsa || this.dsa)) {
				throw new GeneralSecurityException( "Both RSA & DSA is not supported!" );
			}
		}
		
		@Override
		final boolean supportsDSA() {
			return this.dsa;
		}
	},
	/**
	 * 
	 */
	DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1("diffie-hellman-group-exchange-sha1") {
		
		private boolean	rsa	= true;
		
		private boolean	dsa	= true;
		
		@Override
		final AlgorithmImpl createInstance() throws NoSuchAlgorithmException {
			return new DiffieHellmanGroupExchangeAlgorithmImpl( MessageDigest.getInstance( "SHA-1" ) );
		}
		
		@Override
		final String getJceDigestName() {
			return "SHA1";
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			MessageDigest.getInstance( "SHA-1" );
			KeyFactory.getInstance( "DH" );
			KeyPairGenerator.getInstance( "DH" );
			KeyAgreement.getInstance( "DH" );
			try {
				Signature.getInstance( "SHA1withRSA" );
			} catch (final GeneralSecurityException e) {
				this.rsa = false;
			}
			try {
				Signature.getInstance( "SHA1withDSA" );
			} catch (final GeneralSecurityException e) {
				this.dsa = false;
			}
			if (!(this.rsa || this.dsa)) {
				throw new GeneralSecurityException( "Both RSA & DSA is not supported!" );
			}
		}
		
		@Override
		final boolean supportsDSA() {
			return this.dsa;
		}
	},
	/**
	 * 
	 */
	DIFFIE_HELLMAN_GROUP1_SHA1("diffie-hellman-group1-sha1") {
		
		private boolean	rsa	= true;
		
		private boolean	dsa	= true;
		
		@Override
		final AlgorithmImpl createInstance() throws NoSuchAlgorithmException {
			return new DiffieHellmanGroup1AlgorithmImpl( MessageDigest.getInstance( "SHA-1" ) );
		}
		
		@Override
		final String getJceDigestName() {
			return "SHA1";
		}
		
		@Override
		final void internCheckSupported() throws GeneralSecurityException {
			MessageDigest.getInstance( "SHA-1" );
			KeyFactory.getInstance( "DH" );
			KeyPairGenerator.getInstance( "DH" );
			KeyAgreement.getInstance( "DH" );
			try {
				Signature.getInstance( "SHA1withRSA" );
			} catch (final GeneralSecurityException e) {
				this.rsa = false;
			}
			try {
				Signature.getInstance( "SHA1withDSA" );
			} catch (final GeneralSecurityException e) {
				this.dsa = false;
			}
			if (!(this.rsa || this.dsa)) {
				throw new GeneralSecurityException( "Both RSA & DSA is not supported!" );
			}
		}
		
		@Override
		final boolean supportsDSA() {
			return this.dsa;
		}
	},
	//
	;
	
	abstract static class AlgorithmImpl {
		MessageDigest	digest;
		
		KexAlgorithm	kexAlgorithm;
		
		KexHostKey		hostKey;
		
		KexEncryption	encryptionCTS;
		
		KexEncryption	encryptionSTC;
		
		KexMAC			macCTS;
		
		KexMAC			macSTC;
		
		KexCompression	compressionCTS;
		
		KexCompression	compressionSTC;
		
		byte[]			kexSecret;
		
		byte[]			kexHash;
		
		abstract boolean doServer(
				final SshSocketHandler handler,
				final int packetType,
				final byte[] data,
				final int length);
	}
	
	private final static class DiffieHellmanGroup1AlgorithmImpl extends AlgorithmImpl {
		private final static int	SSH_MSG_KEX_DH_G1_INIT	= 30;
		
		private final static int	SSH_MSG_KEX_DH_G1_REPLY	= 31;
		
		private static final byte[]	g						= { 2 };
		
		private static final byte[]	p						= {
																	(byte) 0x00,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xC9,
																	(byte) 0x0F,
																	(byte) 0xDA,
																	(byte) 0xA2,
																	(byte) 0x21,
																	(byte) 0x68,
																	(byte) 0xC2,
																	(byte) 0x34,
																	(byte) 0xC4,
																	(byte) 0xC6,
																	(byte) 0x62,
																	(byte) 0x8B,
																	(byte) 0x80,
																	(byte) 0xDC,
																	(byte) 0x1C,
																	(byte) 0xD1,
																	(byte) 0x29,
																	(byte) 0x02,
																	(byte) 0x4E,
																	(byte) 0x08,
																	(byte) 0x8A,
																	(byte) 0x67,
																	(byte) 0xCC,
																	(byte) 0x74,
																	(byte) 0x02,
																	(byte) 0x0B,
																	(byte) 0xBE,
																	(byte) 0xA6,
																	(byte) 0x3B,
																	(byte) 0x13,
																	(byte) 0x9B,
																	(byte) 0x22,
																	(byte) 0x51,
																	(byte) 0x4A,
																	(byte) 0x08,
																	(byte) 0x79,
																	(byte) 0x8E,
																	(byte) 0x34,
																	(byte) 0x04,
																	(byte) 0xDD,
																	(byte) 0xEF,
																	(byte) 0x95,
																	(byte) 0x19,
																	(byte) 0xB3,
																	(byte) 0xCD,
																	(byte) 0x3A,
																	(byte) 0x43,
																	(byte) 0x1B,
																	(byte) 0x30,
																	(byte) 0x2B,
																	(byte) 0x0A,
																	(byte) 0x6D,
																	(byte) 0xF2,
																	(byte) 0x5F,
																	(byte) 0x14,
																	(byte) 0x37,
																	(byte) 0x4F,
																	(byte) 0xE1,
																	(byte) 0x35,
																	(byte) 0x6D,
																	(byte) 0x6D,
																	(byte) 0x51,
																	(byte) 0xC2,
																	(byte) 0x45,
																	(byte) 0xE4,
																	(byte) 0x85,
																	(byte) 0xB5,
																	(byte) 0x76,
																	(byte) 0x62,
																	(byte) 0x5E,
																	(byte) 0x7E,
																	(byte) 0xC6,
																	(byte) 0xF4,
																	(byte) 0x4C,
																	(byte) 0x42,
																	(byte) 0xE9,
																	(byte) 0xA6,
																	(byte) 0x37,
																	(byte) 0xED,
																	(byte) 0x6B,
																	(byte) 0x0B,
																	(byte) 0xFF,
																	(byte) 0x5C,
																	(byte) 0xB6,
																	(byte) 0xF4,
																	(byte) 0x06,
																	(byte) 0xB7,
																	(byte) 0xED,
																	(byte) 0xEE,
																	(byte) 0x38,
																	(byte) 0x6B,
																	(byte) 0xFB,
																	(byte) 0x5A,
																	(byte) 0x89,
																	(byte) 0x9F,
																	(byte) 0xA5,
																	(byte) 0xAE,
																	(byte) 0x9F,
																	(byte) 0x24,
																	(byte) 0x11,
																	(byte) 0x7C,
																	(byte) 0x4B,
																	(byte) 0x1F,
																	(byte) 0xE6,
																	(byte) 0x49,
																	(byte) 0x28,
																	(byte) 0x66,
																	(byte) 0x51,
																	(byte) 0xEC,
																	(byte) 0xE6,
																	(byte) 0x53,
																	(byte) 0x81,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF,
																	(byte) 0xFF };
		
		private final byte[]		buffer					= new byte[8192];
		
		private final Format		format					= new Format();
		
		DiffieHellmanGroup1AlgorithmImpl(final MessageDigest digest) {
			this.digest = digest;
		}
		
		@Override
		boolean doServer(final SshSocketHandler handler, final int packetType, final byte[] data, final int length) {
			switch (packetType) {
			case SSH_MSG_KEX_DH_G1_INIT: {
				this.format.initialize( data, 0 );
				final BigInteger e = this.format.readMpint();
				final byte[] temp = this.buffer;
				int index = 0;
				try {
					final DHPublicKeySpec keyPublicClientSpec = new DHPublicKeySpec( e,
							new BigInteger( DiffieHellmanGroup1AlgorithmImpl.p ),
							new BigInteger( DiffieHellmanGroup1AlgorithmImpl.g ) );
					final PublicKey keyPublicClient = KeyFactory.getInstance( "DH" )
							.generatePublic( keyPublicClientSpec );
					
					// Use the values to generate a key pair
					final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "DH" );
					keyPairGenerator.initialize( ((DHPublicKey) keyPublicClient).getParams() );
					final KeyPair keyPair = keyPairGenerator.generateKeyPair();
					final KeyAgreement ka = KeyAgreement.getInstance( "DH" );
					ka.init( keyPair.getPrivate() );
					ka.doPhase( keyPublicClient, true );
					
					final BigInteger f = ((DHPublicKey) keyPair.getPublic()).getY();
					
					// Generate the secret key
					final byte[] secret = ka.generateSecret();
					this.kexSecret = secret;
					
					// update digest
					{
						this.digest.update( temp, 0, Format.writeMpint( e, temp, 0 ) );
						this.digest.update( temp, 0, Format.writeMpint( f, temp, 0 ) );
						this.digest.update( temp, 0, Format.writeString( secret, temp, 0 ) );
					}
					
					this.kexHash = this.digest.digest();
					
					final Signature signature = Signature.getInstance( this.kexAlgorithm.getJceDigestName()
							+ "with"
							+ this.hostKey.getJceName() );
					signature.initSign( this.hostKey.getPrivateKey() );
					signature.update( this.kexHash );
					
					{
						// type
						temp[index++] = DiffieHellmanGroup1AlgorithmImpl.SSH_MSG_KEX_DH_G1_REPLY;
						// server public host key
						final byte[] key = this.hostKey.getPublicSshKey();
						System.arraycopy( key, 0, temp, index, key.length );
						index += key.length;
						// f
						index = Format.writeMpint( f, temp, index );
						// HASH
						final byte[] signatureBytes = signature.sign();
						final byte[] sshKeyTypeName = this.hostKey.getPublicSshType();
						index = Format.writeUint32( 4 + sshKeyTypeName.length + 4 + signatureBytes.length, temp, index );
						index = Format.writeString( sshKeyTypeName, temp, index );
						index = Format.writeString( signatureBytes, temp, index );
					}
				} catch (final GeneralSecurityException ex) {
					ex.printStackTrace();
					return false;
				}
				return handler.sendPacket( temp, 0, index );
			}
			}
			return false;
		}
	}
	
	private final static class DiffieHellmanGroupExchangeAlgorithmImpl extends AlgorithmImpl {
		private final static int	SSH_MSG_KEX_DH_GEX_REQUEST_OLD	= 30;
		
		private final static int	SSH_MSG_KEX_DH_GEX_GROUP		= 31;
		
		private final static int	SSH_MSG_KEX_DH_GEX_INIT			= 32;
		
		private final static int	SSH_MSG_KEX_DH_GEX_REPLY		= 33;
		
		private final static int	SSH_MSG_KEX_DH_GEX_REQUEST		= 34;
		
		private final Format		format							= new Format();
		
		private final byte[]		buffer							= new byte[8192];
		
		private DHParameterSpec		dhSpec;
		
		DiffieHellmanGroupExchangeAlgorithmImpl(final MessageDigest digest) {
			this.digest = digest;
		}
		
		@Override
		boolean doServer(final SshSocketHandler handler, final int packetType, final byte[] data, final int length) {
			switch (packetType) {
			case SSH_MSG_KEX_DH_GEX_REQUEST_OLD: {
				this.format.initialize( data, 0 );
				final int groupSize = this.format.readUint32();
				final byte[] temp = this.buffer;
				this.digest.update( temp, 0, Format.writeUint32( groupSize, temp, 0 ) );
				return this.sendGexGroupPacket( handler, groupSize );
			}
			case SSH_MSG_KEX_DH_GEX_REQUEST: {
				this.format.initialize( data, 0 );
				final int groupSizeMin = this.format.readUint32();
				final int groupSizeBest = this.format.readUint32();
				final int groupSizeMax = this.format.readUint32();
				final byte[] temp = this.buffer;
				this.digest.update( temp, 0, Format.writeUint32( groupSizeMin, temp, 0 ) );
				this.digest.update( temp, 0, Format.writeUint32( groupSizeBest, temp, 0 ) );
				this.digest.update( temp, 0, Format.writeUint32( groupSizeMax, temp, 0 ) );
				return this.sendGexGroupPacket( handler, groupSizeBest );
			}
			case SSH_MSG_KEX_DH_GEX_INIT: {
				this.format.initialize( data, 0 );
				final BigInteger e = this.format.readMpint();
				return this.sendGexReply( handler, e );
			}
			default:
				return false;
			}
		}
		
		private boolean sendGexGroupPacket(final SshSocketHandler handler, final int groupSize) {
			final byte[] temp = this.buffer;
			int index = 0;
			try {
				final AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator
						.getInstance( "DH" );
				algorithmParameterGenerator.init( Math.min( groupSize, 1024 ) );
				final AlgorithmParameters algorithmParameter = algorithmParameterGenerator.generateParameters();
				this.dhSpec = algorithmParameter.getParameterSpec( DHParameterSpec.class );
			} catch (final GeneralSecurityException e) {
				e.printStackTrace();
				return false;
			}
			{
				this.digest.update( this.hostKey.getPublicSshKey() );
				// type
				temp[index++] = DiffieHellmanGroupExchangeAlgorithmImpl.SSH_MSG_KEX_DH_GEX_GROUP;
				// p, safe prime
				index = Format.writeMpint( this.dhSpec.getP(), temp, index );
				// g, generator for subgroup in GF(p)
				index = Format.writeMpint( this.dhSpec.getG(), temp, index );
				// update digest
				this.digest.update( temp, 1, index - 1 );
			}
			return handler.sendPacket( temp, 0, index );
		}
		
		private boolean sendGexReply(final SshSocketHandler handler, final BigInteger e) {
			final byte[] temp = this.buffer;
			int index = 0;
			try {
				final DHPublicKeySpec keyPublicClientSpec = new DHPublicKeySpec( e,
						this.dhSpec.getP(),
						this.dhSpec.getG() );
				final PublicKey keyPublicClient = KeyFactory.getInstance( "DH" ).generatePublic( keyPublicClientSpec );
				
				// Use the values to generate a key pair
				final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "DH" );
				keyPairGenerator.initialize( ((DHPublicKey) keyPublicClient).getParams() );
				final KeyPair keyPair = keyPairGenerator.generateKeyPair();
				final KeyAgreement ka = KeyAgreement.getInstance( "DH" );
				ka.init( keyPair.getPrivate() );
				ka.doPhase( keyPublicClient, true );
				
				final BigInteger f = ((DHPublicKey) keyPair.getPublic()).getY();
				
				// Generate the secret key
				final byte[] secret = ka.generateSecret();
				this.kexSecret = secret;
				
				// update digest
				{
					this.digest.update( temp, 0, Format.writeMpint( e, temp, 0 ) );
					this.digest.update( temp, 0, Format.writeMpint( f, temp, 0 ) );
					this.digest.update( temp, 0, Format.writeString( secret, temp, 0 ) );
				}
				
				this.kexHash = this.digest.digest();
				
				final Signature signature = Signature.getInstance( this.kexAlgorithm.getJceDigestName()
						+ "with"
						+ this.hostKey.getJceName() );
				signature.initSign( this.hostKey.getPrivateKey() );
				signature.update( this.kexHash );
				
				{
					// type
					temp[index++] = DiffieHellmanGroupExchangeAlgorithmImpl.SSH_MSG_KEX_DH_GEX_REPLY;
					// server public host key
					final byte[] key = this.hostKey.getPublicSshKey();
					System.arraycopy( key, 0, temp, index, key.length );
					index += key.length;
					// f
					index = Format.writeMpint( f, temp, index );
					// HASH
					final byte[] signatureBytes = signature.sign();
					final byte[] sshKeyTypeName = this.hostKey.getPublicSshType();
					index = Format.writeUint32( 4 + sshKeyTypeName.length + 4 + signatureBytes.length, temp, index );
					index = Format.writeString( sshKeyTypeName, temp, index );
					index = Format.writeString( signatureBytes, temp, index );
				}
			} catch (final GeneralSecurityException ex) {
				ex.printStackTrace();
				return false;
			}
			return handler.sendPacket( temp, 0, index );
		}
	}
	
	private final static Map<String, KexAlgorithm>	SUPPORTED_MAP;
	
	/**
	 * 
	 */
	public final static byte[]						KEX;
	static {
		final Map<String, KexAlgorithm> supportedMap = new HashMap<>();
		final StringBuilder supportedString = new StringBuilder();
		for (final KexAlgorithm current : KexAlgorithm.values()) {
			try {
				current.internCheckSupported();
				if (supportedMap.put( current.name, current ) == null) {
					if (supportedString.length() > 0) {
						supportedString.append( ',' );
					}
					supportedString.append( current.name );
				}
				Ssh.LOG.event( "SSH-KEX-ALG", "SUPPORTED", current.name );
			} catch (final GeneralSecurityException e) {
				Ssh.LOG.event( "SSH-KEX-ALG", "UNSUPPORTED", current.name );
			}
		}
		SUPPORTED_MAP = supportedMap;
		KEX = supportedString.toString().getBytes();
	}
	
	final static KexAlgorithm chooseKexAlgorithm(final String kexAlgorithms) {
		for (final StringTokenizer st = new StringTokenizer( kexAlgorithms, "," ); st.hasMoreTokens();) {
			final KexAlgorithm kexAlgorithm = KexAlgorithm.SUPPORTED_MAP.get( st.nextToken() );
			if (kexAlgorithm != null) {
				return kexAlgorithm;
			}
		}
		return null;
	}
	
	private final String	name;
	
	KexAlgorithm(final String name) {
		this.name = name;
	}
	
	abstract AlgorithmImpl createInstance() throws NoSuchAlgorithmException;
	
	abstract String getJceDigestName();
	
	abstract void internCheckSupported() throws GeneralSecurityException;
	
	abstract boolean supportsDSA();
}
