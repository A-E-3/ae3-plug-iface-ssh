package ru.myx.iface.ssh;
import ru.myx.ae3.produce.Produce;
import ru.myx.ae3.status.StatusRegistry;

/**
 * @author myx
 * 
 */
public final class Main {
	
	/**
	 * @param args
	 */
	public static void main(final String[] args) {
		System.out.println( "BOOT: SSH is being initialized..." );
		StatusRegistry.ROOT_REGISTRY.register( new SshStatusProvider() );
		Produce.registerFactory( new SshTargetFactory() );
		System.out.println( "BOOT: SSH OK" );
	}
	
}
