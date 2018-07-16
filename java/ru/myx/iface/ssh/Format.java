package ru.myx.iface.ssh;

import java.math.BigInteger;

final class Format {
	
	final static int writeMpint(final BigInteger p, final byte[] target, int position) {
		final int compare = p.compareTo( BigInteger.ZERO );
		if (compare == 0) {
			target[position++] = 0;
			target[position++] = 0;
			target[position++] = 0;
			target[position++] = 0;
			return position;
		}
		final byte[] bytes = p.toByteArray();
		position = Format.writeUint32( bytes.length, target, position );
		System.arraycopy( bytes, 0, target, position, bytes.length );
		position += bytes.length;
		return position;
	}
	
	final static int writeNameList(final String list, final byte[] target, int position) {
		position = Format.writeUint32( list.length(), target, position );
		for (int i = list.length(), j = 0; i > 0; i--, j++) {
			target[position++] = (byte) list.charAt( j );
		}
		return position;
	}
	
	final static int writeString(final byte[] bytes, final byte[] target, int position) {
		position = Format.writeUint32( bytes.length, target, position );
		System.arraycopy( bytes, 0, target, position, bytes.length );
		position += bytes.length;
		return position;
	}
	
	final static int writeUint32(final int i, final byte[] target, int position) {
		target[position++] = (byte) (i >> 24 & 0xFF);
		target[position++] = (byte) (i >> 16 & 0xFF);
		target[position++] = (byte) (i >> 8 & 0xFF);
		target[position++] = (byte) (i >> 0 & 0xFF);
		return position;
	}
	
	private int		position;
	
	private byte[]	data;
	
	// creates uninitialized reader
	Format() {
		// ignore
	}
	
	final int getOffset() {
		return this.position;
	}
	
	final void initialize(final byte[] data, final int offset) {
		this.position = offset;
		this.data = data;
	}
	
	final byte readByte() {
		return this.data[this.position++];
	}
	
	final BigInteger readMpint() {
		return new BigInteger( this.readString() );
	}
	
	final String readNameList() {
		final int length = this.readUint32();
		final String result = new String( this.data, this.position, length );
		this.position += length;
		return result;
	}
	
	final byte[] readString() {
		final int length = this.readUint32();
		final byte[] bytes = new byte[length];
		System.arraycopy( this.data, this.position, bytes, 0, length );
		this.position += length;
		return bytes;
	}
	
	final int readUint32() {
		return (this.data[this.position++] & 0xFF) << 24
				| (this.data[this.position++] & 0xFF) << 16
				| (this.data[this.position++] & 0xFF) << 8
				| (this.data[this.position++] & 0xFF) << 0;
	}
}
