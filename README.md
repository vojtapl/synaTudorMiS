# Synaptics Tudor Match in Sensor (MiS) reverse engineering

The fingerprint reader in my laptop (06CB:00FF) does not seem to support raw frame capture and export and to only support match on chip authentication and enrollment. This is likely the reason why the current libfprint library does not work with this sensor. The goal is to create a prototype driver. Currently only the python driver partially works, the libfprint integration does not. If you have any questions/additions, feel free to reach out/open a issue/merge request.


### Disclaimer
- THIS PROJECT IS EXPERIMENTAL. ALL WORK IS PROVIDED AS IS, WITH NO LIABILITY IN CASE SOMETHING GOES WRONG, e.g. you can format your sensor host partition and lose the Windows pairing data.
- Please note that some things are not yet changed from to the current sensor, e.g. the iota patches.


### Most likely supported devices
- per synaWudfBioUsbUwp.inf
- 06CB:00C9
- 06CB:00D1
- 06CB:00E7
- 06CB:00FF (tested)
- 06CB:0124
- 06CB:0169 (is in the newer driver - the one currently not being looked into)
- possibly others from non-HP vendors and newer from HP


### What works:
- Everything should work (though there may be bugs).

### What does not work:
- Using the same pairing data/fingerprints in Windows and Linux.
    - This would require an equivalent function to Crypt(Un)ProtectData to encrypt the pairing data before writing to host partition on sensor. Or dumping the pairing data and storing them on Linux as well.

### To-dos:
- common property
    - where does the common property come from
        -> where does the function highLevelSetCommonProptery get its params from
    - what is it for?
- (not important) check for update and update of firmware update
- (not important) find the newest driver version and check for differences
- improve security

### Some notes on how does the sensor work
- Each enrollment is tied to a set of pairing data - template ID, finger ID, windows SID.

### How to reverse-engineer a Windows fingerprint driver
- The first step is to find the name of the device with USB vendor and product IDs and search on the internet. Finding someone's work, even if the devices seem to be only a little bit similar, could be a huge time saver.
- If no one has reverse-engineered the device yet (not even a similar one) then you will have to do it (it is fun though 😀).
- As I only have experience with Synaptics's fingerprint devices, I will base this part on them.
- Having downloaded the **latest** version of the driver (I cannot stress this enough - as some important bug fixes may be missing and you will not want to do this twice), you will want to find more information about it. For example in HP's driver there is a file `synaWudfBioUsbUwp.inf`, which contains all supported devices by USB vendor and product IDs and the driver version.
- The next step is to find the `.dll` files and if there is more than one, than the one, which communicates with the sensor. My advice would be to open them in Ghidra and search in the `Defined String` for something like `usb`. If you find strings containing `WinUSB` you are onto something, if not look into the strings more, until you find something more relevant.
- Another thing to look for is the driver's logging. For that search for `OutputDebugString`, `debug` ... If you find something, worthwhile, you will want to setup for driver debugging with WinDbg (there are other programs too, but this one worked for me; I prefer the newer version as it looks better), see [here](https://flylib.cjom/books/en/3.141.1.164/1/). Then launch WinDbg as administrator and attach to the `WUDFHost.exe` process, but beware there may be more and only one may output what you need. Now you should be greeted to a `ntdll!DbgBrekPoint`, press the `Go` button and hopefully something pops out in the `Command` window. If you get something, you can check the behavior during fingerprint enrollment/authentication/... If you get nothing, it may be, that the debug output is disabled (search in the strings for `IsDebuggerPresent`) or it is enabled via a registry entry.
- Look for functions using the registry - `Reg...`, though in the Synaptics driver I have not found anything interesting.
- Now the most time consuming part - trying to figure out how the driver works. I have only a single piece of advice - get to know the tool you are using, for Ghidra you should look into renaming functions/variables, editing function signatures, (automatically) creating structs, using included structs, naming constants, how to move quickly around functions and so on.
- At some point you will want to see the data in different parts of the program or the data being sent.
  - If the sensor does not use encrypted connection, or you are interested only in the establishing of a TLS session (for decryption you would need to dump the keys from the program), you could use Wireshark. This program will show you the data which passes through a USB connection. For more details see here: (FIXME)[].
  - The other option is to add breakpoints and print the data, when a breakpoint is hit. See (here)[./reverse engineering/SP141455/WinDbg breakpoints/README.md] how to add breakpoints. Then to see what is in some register/memory/... see here: (FIXME)[]. To find where the value is stored, see the `Listing` window in Ghidra and then either the blue window at the start function containing offsets/register names for variables or the instruction parameters bellow.
    - for example we have `BLOB* R8:8 toSendBlob`, so (at least at some point) in the R8 register should be addres of a blob struct
    - we get the address with command `r r8` and with `dq [add address]` we can see the size and pointer to the data
    - to make it easier you can add commands together and get the output immediately, e.g. `db poi(@r8 + 8) Lwo(@r8)` prints only the blob data with the correct size (for more examples see (here)[./reverse engineering/SP141455/WinDbg breakpoints/breakpoints with data dump.txt])
    - remember to make it easier on yourself and add some description to the output with `.echo` or `.printf`
    - for more complete list of commands see (here)[FIXME]
- Hopefully now you should have enough notes to start working on a prototype driver.

### Some notes on how to make a libfprint driver
- As I have not done anything similar before, the asynchronous driver design was quite daunting. If you have it the same, ignore it and write it synchronously (see the `*_sync` function variants).



### Abbreviations used:
- tuid = template UID
- SID = windows security identifier
- FW = firmware
- SBL = ?
- MiS = match in sensor
- qm = Synaptics Quantum Matcher


### Acknowledgment
- The driver is based on [Synaptics Tudor Sensors Reverse Engineering Project](https://github.com/Popax21/synaTudor/tree/rev) by Popax21 and his [Driver Relinking Project](https://github.com/Popax21/synaTudor/tree/relink)
- This blog post: [Reversing a Fingerprint Reader Protocol](https://blog.th0m.as/misc/fingerprint-reversing/) by Thomas Lambertz was very helpful in the beginning.
