/*
 * Created on 28.04.2006
 */
package ru.myx.iface.ssh;

import ru.myx.ae3.binary.TransferSocket;

final class ParserQueue {
	private static final int			LEAF_SIZE					= 16;
	
	private static final int			QUEUE_COUNT					= 16;
	
	private static final int			QUEUE_MASK					= ParserQueue.QUEUE_COUNT - 1;
	
	private final int					queueIndex;
	
	private final SshSocketHandler[]	parsers;
	
	private int							count;
	
	static int							stsInlineParserCreations	= 0;
	
	private static final ParserQueue[]	QUEUES						= ParserQueue.createQueues();
	
	private static int					counter						= 0;
	
	private static final ParserQueue[] createQueues() {
		final ParserQueue[] queues = new ParserQueue[ParserQueue.QUEUE_COUNT];
		for (int i = ParserQueue.QUEUE_MASK; i >= 0; --i) {
			queues[i] = new ParserQueue( i );
		}
		return queues;
	}
	
	static final SshSocketHandler getParser(final TransferSocket socket, final FlowConfiguration configuration) {
		final ParserQueue queue = ParserQueue.QUEUES[--ParserQueue.counter & ParserQueue.QUEUE_MASK];
		return queue.getParserImpl( socket, configuration );
	}
	
	static final void reuseParser(final SshSocketHandler parser, final int queueIndex) {
		ParserQueue.QUEUES[queueIndex].reuseParser( parser );
	}
	
	private ParserQueue(final int queueIndex) {
		this.queueIndex = queueIndex;
		this.parsers = new SshSocketHandler[ParserQueue.LEAF_SIZE];
		for (int i = ParserQueue.LEAF_SIZE - 1; i >= 0; --i) {
			this.parsers[i] = new SshSocketHandler( queueIndex );
			this.count++;
		}
	}
	
	private final SshSocketHandler getParserImpl(final TransferSocket socket, final FlowConfiguration configuration) {
		SshSocketHandler parser;
		synchronized (this) {
			if (this.count > 0) {
				parser = this.parsers[--this.count];
				this.parsers[this.count] = null;
			} else {
				parser = null;
			}
		}
		if (parser == null) {
			ParserQueue.stsInlineParserCreations++;
			parser = new SshSocketHandler( this.queueIndex );
		}
		parser.prepare( socket, configuration );
		return parser;
	}
	
	private final void reuseParser(final SshSocketHandler parser) {
		synchronized (this) {
			if (this.count < ParserQueue.LEAF_SIZE) {
				this.parsers[this.count++] = parser;
			}
		}
	}
}
