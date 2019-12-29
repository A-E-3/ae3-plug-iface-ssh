package ru.myx.iface.ssh;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Random;
import java.util.function.Function;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

import ru.myx.ae3.base.Base;
import ru.myx.ae3.binary.TransferBuffer;
import ru.myx.ae3.binary.TransferSocket;
import ru.myx.ae3.binary.TransferTarget;
import ru.myx.ae3.exec.Exec;
import ru.myx.ae3.exec.ExecProcess;
import ru.myx.ae3.report.Report;

final class SshSocketHandler implements TransferTarget {

	private final static Random RANDOM = new Random();

	private final static byte[] TEMPLATE_KEXINIT;

	private final static int SSH_MSG_KEXINIT = 20;

	private final static int SSH_MSG_NEWKEYS = 21;

	private final static int MDR_READ_PACKET = 0;

	private final static int MDR_READ_PADDING = 1;

	private final static int MDR_READ_PACKET_TYPE = 2;

	private final static int MDR_PACKET_LENGTH_1 = 3;

	private final static int MDR_PACKET_LENGTH_2 = 4;

	private final static int MDR_PACKET_LENGTH_3 = 5;

	private final static int MDR_PACKET_LENGTH_4 = 6;

	private final static int MDR_PADDING_LENGTH = 7;

	private final static int MDR_HELLO_LINE_MODE = 8;

	private final static int MDR_HELLO_LINE_LIMIT = 128;

	private final static int BUFFER_CAPACITY_READ = 35000;

	private final static int BUFFER_CAPACITY_WRITE = 35000;

	private static final byte[] SERVER_VERSION_BYTES = "SSH-2.0-AE3 PURE_JAVA".getBytes();

	private static final byte[] SERVER_VERSION_CRLF_BYTES = "SSH-2.0-AE3 PURE_JAVA\r\n".getBytes();

	static int stBadRequests = 0;

	static int stExpands = 0;

	static int stRequests = 0;

	static int stUnexpectedFinalizations = 0;

	static {
		{
			final int length = 1 + 16 + 4 + KexAlgorithm.KEX.length + 4 + KexHostKey.KEX.length + 2 * (4 + KexEncryption.KEX.length) + 2 * (4 + KexMAC.KEX.length)
					+ 2 * (4 + KexCompression.KEX.length) + 4 + 4 + 1 + 4;
			final byte[] temp = new byte[length];
			int index = 0;
			temp[index++] = SshSocketHandler.SSH_MSG_KEXINIT;
			index += 16;
			index = Format.writeString(KexAlgorithm.KEX, temp, index);
			index = Format.writeString(KexHostKey.KEX, temp, index);
			index = Format.writeString(KexEncryption.KEX, temp, index);
			index = Format.writeString(KexEncryption.KEX, temp, index);
			index = Format.writeString(KexMAC.KEX, temp, index);
			index = Format.writeString(KexMAC.KEX, temp, index);
			index = Format.writeString(KexCompression.KEX, temp, index);
			index = Format.writeString(KexCompression.KEX, temp, index);
			// languages_client_to_server
			index = Format.writeUint32(0, temp, index);
			// languages_server_to_client
			index = Format.writeUint32(0, temp, index);
			// first_kex_packet_follows
			temp[index++] = (byte) 0;
			// uint32 == 0
			index = Format.writeUint32(0, temp, index);
			if (index != length) {
				throw new IllegalStateException("Wrong KEXINIT template length!");
			}
			TEMPLATE_KEXINIT = temp;
		}
	}

	private final int queueIndex;

	private int readPacketPadding;

	private int readBufferLimit = SshSocketHandler.MDR_HELLO_LINE_LIMIT;

	private int readMode = SshSocketHandler.MDR_HELLO_LINE_MODE;

	private final ExecProcess process = Exec.createProcess(Ssh.CTX, "ssh connection");

	private TransferSocket socket;

	private int readBufferType;

	private final byte[] readBuffer = new byte[SshSocketHandler.BUFFER_CAPACITY_READ];

	private int readBufferPosition = 0;

	private final byte[] writeBuffer = new byte[SshSocketHandler.BUFFER_CAPACITY_WRITE];

	private int writeBufferPosition = 0;

	private String clientVersion;

	private KexAlgorithm.AlgorithmImpl kexImpl;

	private Cipher currentEncryptionCTS;

	private Cipher currentEncryptionSTC;

	private Inflater currentCompressionCTS;

	private Deflater currentCompressionSTC;

	private Mac currentMacCTS;

	private Mac currentMacSTC;

	private final byte[] writeBufferTemp = new byte[256];

	private byte[] sessionId;

	SshSocketHandler(final int queueIndex) {

		this.queueIndex = queueIndex;
	}

	@Override
	public void abort(final String reason) {

		this.socket.abort(reason);
	}

	@Override
	public boolean absorb(final int i) {

		try {
			return this.nextSsh(i);
		} catch (final GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean absorbArray(final byte[] array, final int off, final int len) {

		try {
			for (int i = off, j = len; j > 0; --j, ++i) {
				if (!this.nextSsh(array[i] & 0xFF)) {
					return false;
				}
			}
			return true;
		} catch (final GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean absorbBuffer(final TransferBuffer buffer) {

		try {
			final byte[] bytes = buffer.toDirectArray();
			for (int i = 0, j = bytes.length; j > 0; --j, ++i) {
				if (!this.nextSsh(bytes[i] & 0xFF)) {
					return false;
				}
			}
			return true;
		} catch (final GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean absorbNio(final ByteBuffer buffer) {

		try {
			final byte[] bytes = new byte[buffer.remaining()];
			buffer.get(bytes);
			/** TODO: check if this actually is faster */
			for (int i = 0, j = bytes.length; j > 0; --j, ++i) {
				if (!this.nextSsh(bytes[i] & 0xFF)) {
					return false;
				}
			}
			return true;
		} catch (final GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		} catch (final Throwable t) {
			t.printStackTrace();
			return false;
		}
	}

	@Override
	public void close() {

		this.socket.close();
	}

	@Override
	public <A, R> boolean enqueueAction(final ExecProcess ctx, final Function<A, R> function, final A argument) {

		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void force() {

		// TODO Auto-generated method stub
	}

	private final boolean nextSsh(final int i) throws GeneralSecurityException {

		switch (this.readMode) {
			case MDR_READ_PACKET :
				this.readBuffer[this.readBufferPosition++] = (byte) i;
				if (--this.readBufferLimit == 0) {
					this.readMode = SshSocketHandler.MDR_READ_PADDING;
				}
				return true;
			case MDR_READ_PADDING :
				if (--this.readPacketPadding == 0) {
					this.readBufferLimit = this.readBufferPosition;
					this.readBufferPosition = 0;
					this.readMode = SshSocketHandler.MDR_PACKET_LENGTH_1;
					if (this.kexImpl != null) {
						if (this.readBufferType == SshSocketHandler.SSH_MSG_NEWKEYS) {
							final byte[] K = this.kexImpl.kexSecret;
							final byte[] H = this.kexImpl.kexHash;
							if (this.sessionId == null) {
								this.sessionId = new byte[H.length];
								System.arraycopy(H, 0, this.sessionId, 0, H.length);
							}

							final MessageDigest digest = this.kexImpl.digest;
							/* Initial IV CTS: HASH (K || H || "A" || sessionId) Initial IV STC:
							 * HASH (K || H || "B" || sessionId) Encryption key CTS: HASH (K || H ||
							 * "C" || sessionId) Encryption key STC: HASH (K || H || "D" ||
							 * sessionId) Integrity key CTS: HASH (K || H || "E" || sessionId)
							 * Integrity key STC: HASH (K || H || "F" || sessionId) */
							int index = 0;
							final byte[] temp = this.readBuffer;
							index = Format.writeString(K, temp, index);
							index = Format.writeString(H, temp, index);
							final int letterPosition = index++;
							index = Format.writeString(this.sessionId, temp, index);

							this.readBuffer[letterPosition] = 'A';
							digest.update(temp, 0, index);
							final byte[] ivCTS = digest.digest();
							this.readBuffer[letterPosition] = 'B';
							digest.update(temp, 0, index);
							final byte[] ivSTC = digest.digest();
							this.readBuffer[letterPosition] = 'C';
							digest.update(temp, 0, index);
							final byte[] ekCTS = digest.digest();
							this.readBuffer[letterPosition] = 'D';
							digest.update(temp, 0, index);
							final byte[] ekSTC = digest.digest();
							this.readBuffer[letterPosition] = 'E';
							digest.update(temp, 0, index);
							final byte[] ikCTS = digest.digest();
							this.readBuffer[letterPosition] = 'F';
							digest.update(temp, 0, index);
							final byte[] ikSTC = digest.digest();

							this.currentEncryptionCTS = this.kexImpl.encryptionCTS == null
								? null
								: this.kexImpl.encryptionCTS.createCipher(Cipher.DECRYPT_MODE, ekCTS, ivCTS);
							this.currentEncryptionSTC = this.kexImpl.encryptionSTC == null
								? null
								: this.kexImpl.encryptionSTC.createCipher(Cipher.ENCRYPT_MODE, ekSTC, ivSTC);
							this.currentCompressionCTS = null;
							this.currentCompressionSTC = null;
							this.currentMacCTS = this.kexImpl.macCTS == null
								? null
								: this.kexImpl.macCTS.createMac(ikCTS);
							this.currentMacSTC = this.kexImpl.macSTC == null
								? null
								: this.kexImpl.macSTC.createMac(ikSTC);
							this.kexImpl = null;
							this.sendPlain("Not supported yet!");
							return false;
						}
						return this.kexImpl.doServer(this, this.readBufferType, this.readBuffer, this.readBufferLimit);
					}
					switch (this.readBufferType) {
						case SSH_MSG_KEXINIT : // 20
							return this.onKexInit();
						default :
							this.sendDump("packet(type=" + this.readBufferType + ")", this.readBuffer, 0, this.readBufferLimit);
					}
				}
				return true;
			case MDR_READ_PACKET_TYPE :
				System.out.println("PACKET_TYPE: " + i);
				this.readBufferType = i;
				this.readMode = this.readBufferLimit == 0
					? SshSocketHandler.MDR_READ_PADDING
					: SshSocketHandler.MDR_READ_PACKET;
				return true;
			case MDR_PACKET_LENGTH_1 :
				this.readBufferLimit = i;
				this.readMode = SshSocketHandler.MDR_PACKET_LENGTH_2;
				return true;
			case MDR_PACKET_LENGTH_2 :
				this.readBufferLimit = (this.readBufferLimit << 8) + i;
				this.readMode = SshSocketHandler.MDR_PACKET_LENGTH_3;
				return true;
			case MDR_PACKET_LENGTH_3 :
				this.readBufferLimit = (this.readBufferLimit << 8) + i;
				this.readMode = SshSocketHandler.MDR_PACKET_LENGTH_4;
				return true;
			case MDR_PACKET_LENGTH_4 :
				this.readBufferLimit = (this.readBufferLimit << 8) + i;
				System.out.println("PACKET LENGTH: " + this.readBufferLimit);
				if (this.readBufferLimit >= 35000) {
					this.sendPlain("Packet size too big!");
					return false;
				}
				this.readMode = SshSocketHandler.MDR_PADDING_LENGTH;
				return true;
			case MDR_PADDING_LENGTH :
				this.readPacketPadding = i;
				this.readBufferLimit -= i + 1 + 1;
				this.readBufferPosition = 0;
				Ssh.LOG.event(Ssh.PNAME_SSH, "DEBUG", "PADDING LENGTH: " + this.readPacketPadding);
				this.readMode = SshSocketHandler.MDR_READ_PACKET_TYPE;
				return true;
			case MDR_HELLO_LINE_MODE :
				switch (i) {
					case 10 :
						this.clientVersion = new String(this.readBuffer, 0, this.readBufferPosition);
						this.readBufferPosition = 0;
						this.sendKexPacket();
						this.readMode = SshSocketHandler.MDR_PACKET_LENGTH_1;
						return true;
					case 13 :
						// skip
						return true;
					default :
						if (--this.readBufferLimit == 0) {
							this.sendPlain("Data limit exceeded - connection close!\r\n");
							return false;
						}
						this.readBuffer[this.readBufferPosition++] = (byte) i;
						return true;
				}
			default :
		}
		return false;
	}

	private boolean onKexInit() throws GeneralSecurityException {

		final KexAlgorithm.AlgorithmImpl kexImpl;
		{
			final Format format = new Format();
			format.initialize(this.readBuffer, 16);
			final KexAlgorithm kexAlgorithm = KexAlgorithm.chooseKexAlgorithm(format.readNameList());
			if (kexAlgorithm == null) {
				this.sendPlain("No common KEX algorithm found!");
				return false;
			}
			kexImpl = kexAlgorithm.createInstance();
			kexImpl.kexAlgorithm = kexAlgorithm;
			kexImpl.hostKey = KexHostKey.chooseKexHostKey(kexAlgorithm, format.readNameList());
			if (kexImpl.hostKey == null) {
				this.sendPlain("No common host key algorithm found!");
				return false;
			}
			kexImpl.encryptionCTS = KexEncryption.chooseKexEncryption(format.readNameList());
			if (kexImpl.encryptionCTS == null) {
				this.sendPlain("No common encryption CTS algorithm found!");
				return false;
			}
			kexImpl.encryptionSTC = KexEncryption.chooseKexEncryption(format.readNameList());
			if (kexImpl.encryptionSTC == null) {
				this.sendPlain("No common encryption STC algorithm found!");
				return false;
			}
			kexImpl.macCTS = KexMAC.chooseKexMAC(format.readNameList());
			if (kexImpl.macCTS == null) {
				this.sendPlain("No common MAC CTS algorithm found!");
				return false;
			}
			kexImpl.macSTC = KexMAC.chooseKexMAC(format.readNameList());
			if (kexImpl.macSTC == null) {
				this.sendPlain("No common MAC STC algorithm found!");
				return false;
			}
			kexImpl.compressionCTS = KexCompression.chooseKexCompression(format.readNameList());
			if (kexImpl.compressionCTS == null) {
				this.sendPlain("No common compression CTS algorithm found!");
				return false;
			}
			kexImpl.compressionSTC = KexCompression.chooseKexCompression(format.readNameList());
			if (kexImpl.compressionSTC == null) {
				this.sendPlain("No common compression STC algorithm found!");
				return false;
			}
			// languages Client To Server - ignored
			format.readNameList();
			// languages Server To Client - ignored
			format.readNameList();
			final boolean firstKexPacketFollows = format.readByte() != 0;
			final int reservedUint32 = format.readUint32();
			if (reservedUint32 != 0) {
				this.sendPlain("Reserved UINT32 of KEX packet should be equal to zero!");
				return false;
			}
			Ssh.LOG.event(Ssh.PNAME_SSH, "DEBUG", "first_kex_packet_follows        : " + firstKexPacketFollows);
			Ssh.LOG.event(Ssh.PNAME_SSH, "DEBUG", "kex_algorithm                   : " + kexAlgorithm);
		}
		this.kexImpl = kexImpl;
		{
			final byte[] temp = this.writeBufferTemp;
			{
				final byte[] bytes = this.clientVersion.getBytes();
				this.kexImpl.digest.update(temp, 0, Format.writeUint32(bytes.length, temp, 0));
				this.kexImpl.digest.update(bytes, 0, bytes.length);
			}
			{
				final byte[] bytes = SshSocketHandler.SERVER_VERSION_BYTES;
				this.kexImpl.digest.update(temp, 0, Format.writeUint32(bytes.length, temp, 0));
				this.kexImpl.digest.update(bytes, 0, bytes.length);
			}
			{
				this.kexImpl.digest.update(temp, 0, Format.writeUint32(this.readBufferLimit + 1, temp, 0));
				this.kexImpl.digest.update((byte) this.readBufferType);
				this.kexImpl.digest.update(this.readBuffer, 0, this.readBufferLimit);
			}
			{
				final byte[] kexPayload = (byte[]) Base.getJava(this.process, "$kexPayload", null);
				this.process.baseDelete("$kexPayload");
				final int length = kexPayload.length;
				this.kexImpl.digest.update(temp, 0, Format.writeUint32(length, temp, 0));
				this.kexImpl.digest.update(kexPayload, 0, length);
			}
		}
		return true;
	}

	final void prepare(final TransferSocket socket, final FlowConfiguration configuration) {

		this.socket = socket;
		socket.getTarget().absorbArray(SshSocketHandler.SERVER_VERSION_CRLF_BYTES, 0, SshSocketHandler.SERVER_VERSION_CRLF_BYTES.length);
		Ssh.LOG.event(Ssh.PNAME_SSH, "CONNECT", "connection: " + socket);
	}

	final void reconnect() {

		if (this.socket.isOpen()) {
			this.socket.getSource().connectTarget(this);
		}
	}

	private void sendDump(final String prefix, final byte[] bytes, final int off, final int len) {

		final StringBuilder builder = new StringBuilder();
		builder.append(this.socket);
		builder.append("\r\n");
		builder.append(prefix);
		builder.append(' ');
		builder.append(len);
		builder.append(" bytes\r\n");
		for (int i = off, j = len; j > 0; --j, ++i) {
			final int x = bytes[i] & 0xFF;
			if (x < 16) {
				builder.append('0');
			}
			builder.append(Integer.toHexString(x)).append(' ').append(' ');
		}
		builder.append("\r\n");
		for (int i = off, j = len; j > 0; --j, ++i) {
			final int x = bytes[i] & 0xFF;
			if (x < 100) {
				builder.append('0');
				if (x < 10) {
					builder.append('0');
				}
			}
			builder.append(Integer.toString(x)).append(' ');
		}
		builder.append("\r\n");
		for (int i = off, j = len; j > 0; --j, ++i) {
			final int x = bytes[i] & 0xFF;
			builder.append(
					Character.isISOControl(x)
						? '.'
						: (char) x)
					.append(' ').append(' ').append(' ');
		}
		Ssh.LOG.event(Ssh.PNAME_SSH, "DUMP", builder.toString());
		builder.append("\r\n");
	}

	private final boolean sendKexPacket() {

		final byte[] temp = new byte[SshSocketHandler.TEMPLATE_KEXINIT.length];
		System.arraycopy(SshSocketHandler.TEMPLATE_KEXINIT, 0, temp, 0, temp.length);
		// cookie
		for (int i = 16; i > 0; --i) {
			temp[i] = (byte) SshSocketHandler.RANDOM.nextInt();
		}
		// put payload to process
		{
			this.process.baseDefine("$kexPayload", Base.forUnknown(temp));
		}
		return this.sendPacket(temp, 0, temp.length);
	}

	final boolean sendPacket(final byte[] payload, final int payloadOffset, final int payloadLength) {

		if (this.currentCompressionSTC != null) {
			// !!! implement compression
			throw new UnsupportedOperationException();
		}
		final Cipher cipher = this.currentEncryptionSTC;
		final int padding;
		{
			final int chunkSize = cipher == null
				? 8
				: Math.min(cipher.getBlockSize(), 8);
			final int paddingNeeded = (int) (Math.ceil((payloadLength + 5) / (double) chunkSize) * chunkSize) - (payloadLength + 5);
			padding = paddingNeeded < 4
				? paddingNeeded + chunkSize
				: paddingNeeded;
		}
		{
			final byte[] target = cipher == null
				? this.writeBuffer
				: this.writeBufferTemp;
			{
				final int i = payloadLength + padding + 1;
				target[0] = (byte) (i >> 24 & 0xFF);
				target[1] = (byte) (i >> 16 & 0xFF);
				target[2] = (byte) (i >> 8 & 0xFF);
				target[3] = (byte) (i >> 0 & 0xFF);
				System.out.println("i=" + i + ", payload=" + payloadLength + ", padding=" + padding);
			}
			target[4] = (byte) padding;
			if (cipher == null) {
				System.arraycopy(payload, payloadOffset, target, 5, payloadLength);
				this.writeBufferPosition = 5 + payloadLength;
				for (int j = padding; j > 0; j--) {
					target[this.writeBufferPosition++] = (byte) SshSocketHandler.RANDOM.nextInt();
				}
			} else {
				try {
					this.writeBufferPosition = cipher.update(this.writeBufferTemp, 0, 5, this.writeBuffer);
					this.writeBufferPosition += cipher.update(payload, payloadOffset, payloadLength, this.writeBuffer, this.writeBufferPosition);
					for (int j = padding - 1; j >= 0; j--) {
						target[j] = (byte) SshSocketHandler.RANDOM.nextInt();
					}
					this.writeBufferPosition += cipher.update(this.writeBufferTemp, 0, padding, this.writeBuffer, this.writeBufferPosition);
				} catch (final ShortBufferException e) {
					Report.exception(Ssh.PNAME_SSH, "on sendPacket", e);
					return false;
				}
			}
		}
		this.sendDump(">>PACKET", this.writeBuffer, 0, this.writeBufferPosition);
		return this.socket.getTarget().absorbArray(this.writeBuffer, 0, this.writeBufferPosition);
	}

	private void sendPlain(final String text) {

		final byte[] bytes = text.getBytes();
		this.socket.getTarget().absorbArray(bytes, 0, bytes.length);
	}

	@Override
	public final String toString() {

		return "SSH PARSER TARGET(" + System.identityHashCode(this) + ")";
	}
}
