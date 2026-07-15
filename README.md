# ae3-plug-iface-ssh

An AE3 interface plugin implementing the SSH protocol from scratch: key-exchange pieces (`KexAlgorithm`, `KexEncryption`, `KexMAC`, `KexCompression`, `KexHostKey`), `Ssh`/`SshSocketHandler`/`SshSocketTarget` for the connection itself, `SshTargetFactory` to set it up.
