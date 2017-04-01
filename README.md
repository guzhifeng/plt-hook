# plt-hook
**Tool for injecting a shared object into a Linux process, shared library substitution, and runtime plt function hook**

* the original idea is inspired by [linux-inject](https://github.com/gaffe23/linux-inject), but more than injection. Except for shared library runtime injection, plt-hook also support runtime plt function hook and shared library substitution. 

* Performs injection using `ptrace()` rather than `LD_PRELOAD`, since the target process is already running at the time of injection

* Supports x86_64

* Does not require the target process to have been built with `-ldl` flag, because it loads the shared object using `__libc_dlopen_mode()` from libc rather than `dlopen()` from libdl

## Caveat about `ptrace()`

* On many Linux distributions, the kernel is configured by default to prevent any process from calling `ptrace()` on another process that it did not create (e.g. via `fork()`).

* This is a security feature meant to prevent exactly the kind of mischief that this tool causes.

* You can temporarily disable it until the next reboot using the following command:

        echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

## Compiling

* Simply running `make` should automatically select and build for the correct architecture, but if this fails (or you would like to select the target manually), run one of the following make commands:

    * x86_64:

            make x86_64

## Usage

    	./inject [-n process-name] [-p pid] [original-library] [library-to-inject]

## Sample

* In one terminal, start up the sample target app, which simply outputs "sleeping..." each second:

        ./sample-target

* In another terminal, inject sample-library.so into the target app:

        ./inject -n sample-target libsample.so  libsampleupdate.so

*  The output should look something like this:

 * First terminal: 
 
			$ ./sample-target 
			call the addition: 7
			main thread: result = 7
			call the addition: 7
			child thread: result = 7
			call the addition: 7
			main thread: result = 7
			call the addition: 7
			child thread: result = 7
			call the addition: 7
			main thread: result = 7
			...

 * Second terminal:
   
 			$ ./inject -n sample-target libsample.so libsampleupdate.so
			targeting process "sample-target" with pid 3267
			symbol need to be replaced:
			libsample
			process 3267 has 2 tasks
			attached to all threads.
			"libsampleupdate.so" successfully injected
			libsample is substituted
			detached from all threads.
			$

 * On first terminal, it start printing out the changed function result.
 
			...  
			child thread: result = 7
			call the addition: 7
			main thread: result = 7
			call the addition: 7
			main thread: result = 7
			call the multiplication: 8
			child thread: result = 8
			call the multiplication: 8
			main thread: result = 8
			call the multiplication: 8
			main thread: result = 8
			...

* If the injection fails, make sure your machine is configured to allow processes to `ptrace()` other processes that they did not create. See the "Caveat about `ptrace()`" section above. 

* Please check 'ldconfig -v' result, your target process should be able to recognize the to-be-injected library path you specified.

* You can verify that the injection was successful by checking `/proc/[pid]/maps`:  

        $ cat /proc/$(pgrep sample-target)/maps  
        [...]  
		7f2c95901000-7f2c95902000 r-xp 00000000 08:12 47196963                   /data/home/zhuozh/plt-hook/libsampleupdate.so  
		7f2c95902000-7f2c95b01000 ---p 00001000 08:12 47196963                   /data/home/zhuozh/plt-hook/libsampleupdate.so  
		7f2c95b01000-7f2c95b02000 r--p 00000000 08:12 47196963                   /data/home/zhuozh/plt-hook/libsampleupdate.so  
		7f2c95b02000-7f2c95b03000 rw-p 00001000 08:12 47196963                   /data/home/zhuozh/plt-hook/libsampleupdate.so  
        [...]

* You can also attach `gdb` to the target app and run `info sharedlibrary` to see what shared libraries the process currently has loaded:

        $ gdb -p $(pgrep sample-target)
        [...]
		(gdb) info sharedlibrary 
		From                To                  Syms Read   Shared Object Library
		0x00007fed695ba5e0  0x00007fed695ba708  Yes         ./libsample.so
		0x00007fed693a38a0  0x00007fed693ae784  Yes         /lib64/libpthread.so.0
		0x00007fed68ffc3b0  0x00007fed6914111f  Yes         /lib64/libc.so.6
		0x00007fed697bcaf0  0x00007fed697d6520  Yes         /lib64/ld-linux-x86-64.so.2
		0x00007fed685da5e0  0x00007fed685da704  Yes         /data/home/zhuozh/plt-hook/libsampleupdate.so
        (gdb)

## TODOs / Known Issues
* Support only X86_64 version

* Support more distros
 * Only tested on Centos 7.2

* Possibly support more architectures?
