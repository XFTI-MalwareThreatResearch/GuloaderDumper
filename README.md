# GuloaderDumper
Windows Kernel Driver for dumping guloader payloads automatically

WARNING: When used properly, this project will execute a guloader sample on a victim computer.  Guloader is malware.  The payload it delivers will be malicious.  The computer must be connected to the internet in order for the tool to work.  We highly recommend you do so in a secure, isolated environment that is non attributable to the user.


GuloaderDumper is a Windows Kernel Module that can be utilized to automatically dump payloads from the Guloader commodity loader.

GuloaderDumper works by tracking the child processes of the initial guloader execution.  Once guloader attempts to download its encrypted payload from the C2 server, GuloaderDumper will suspend the process and dump the resulting payload.  The payload may execute for a short period before it is suspended.  

GuloaderDumper takes advantage of how Guloader injects its payloads into other processes.  After Guloader injects its payload, it will close its internet connection.  This sends a signal to the dumper module that it is time to attempt to dump a payload.  Once that signal is sent, GuloaderDumper will search the target process's PEB for loaded modules.  One of these modules will match the injected guloader payload.  Because the loaded modules list is primarily intended for loaded DLLs, GuloaderDumper is able to detect which module is the guloader payload itself.  This is possible because Guloader will leave the injected payload's IMAGE_FILE_HEADER.Characteristics unchanged, which will usually show that the memory mapped PE is not a DLL file.  This target module is then cleaned up and dumped by GuloaderDumper.

Because GuloaderDumper resides in the kernel, it avoids almost all of the anti debug checks that Guloader has.  This prevents Guloader from terminating early due to VM or analysis detection.


How to Use:
NOTE: It is highly recommended to use a clean VM on an isolated network that cannot be traced back to you.  The network should be isolated from any other devices.  Again, this program will execute malware.  It will contact malicious domains.  Be careful.

1. Enable test mode on the victim VM through the following command: bcdedit /set testsigning on
    Because this is a kernel module, test signing must be on because it is not signed with a valid certificate.
2. Follow the steps here to download and install the Windows Driver Kit: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    This is required in order to properly insert the kernel module.
3. Compile GuloaderDumper for your target system.  Visual Studio can be used to do this.  The output should be a folder that contains a few artifacts: a .cat file, a .sys file (the driver itself) and a .inf file.  All are required in order to properly insert.
4. Install GuloaderDumper using devcon install.  devcon is installed when the WDK is installed.  It is usually located somewhere within the path C:\Program Files (x86)\Windows Kits\10\Tools\<version number>\x64\devcon.exe .  An identifier (can be anything valid, e.x Root\GuloaderDumper) and the path of the .inf file generated during compilation is required.  There should not be any errors on devcon install.
5. Place the python file runner.py somewhere on the system.  Doesnt particularly matter where.
6. Place the guloader sample at the hardcoded path "exe_path" within runner.py.
7. Before executing, it may be a good idea to double check C:\logfile.txt in order to ensure GuloaderDumper has not reported any errors.  Sometimes when you restart the computer GuloaderDumper will initialize improperly and report an error due to the order of how Windows loads various components.  In order to fix this, simply restart the GuloaderDumper service and check the logfile again.
8. Execute the runner.py script.  Once complete, the payload will be written to C:\output.bin.

GuloaderDumper will not work properly if initialization fails.  Because Guloader requires internet to download its payloads, GuloaderDumper requires internet as well.  Be careful.

