package ru.myx.iface.ssh;

import ru.myx.ae3.binary.TransferSocket;
import ru.myx.ae3.binary.TransferTarget;
import ru.myx.ae3.flow.ObjectTarget;
import ru.myx.ae3.report.Report;

/*
 * Created on 30.11.2005

 */
final class SshSocketTarget implements ObjectTarget<TransferSocket> {
	
	private static final String OWNER = "SSH_TARGET";

	private final FlowConfiguration configuration;

	SshSocketTarget(final boolean ignoreTargetPort, final boolean ignoreGzip, final boolean ignoreKeepAlive, final boolean reverseProxied) {
		this.configuration = new FlowConfiguration(Ssh.PNAME_SSH, ignoreTargetPort, ignoreGzip, ignoreKeepAlive, reverseProxied);
		if (Report.MODE_DEBUG) {
			Ssh.LOG.event(SshSocketTarget.OWNER, "INITIALIZING", "ignoreTargetPort=" + ignoreTargetPort);
		}
	}

	@Override
	public final boolean absorb(final TransferSocket socket) {
		
		final TransferTarget parser = ParserQueue.getParser(socket, this.configuration);
		if (Report.MODE_DEBUG) {
			Ssh.LOG.event(SshSocketTarget.OWNER, "CONNECTING", "socket=" + socket.getIdentity() + ", parser=" + parser);
		}
		final boolean result = socket.getSource().connectTarget(parser);
		if (result) {
			SshStatusProvider.stConnections++;
		}
		return result;
	}

	@Override
	public final Class<? extends TransferSocket> accepts() {
		
		return TransferSocket.class;
	}

	@Override
	public final String toString() {
		
		return SshSocketTarget.OWNER;
	}
}
