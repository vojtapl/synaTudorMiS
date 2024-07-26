# Synaptics Tudor Match in Sensor (MiS) reverse engineering

The fingerprint reader in my laptop (06CB:00FF) does not seem to support raw frame capture and export and to only support match on chip authentication and enrollment. This is likely the reason why the current libfprint library does not work with this sensor. The goal is to create a prototype driver. Currently only the python driver partially works, the libfprint integration does not.


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


### What works:

- Enroll, authentication.
- Some other misc commands.

### What does not work:
- More complex working with data partition - saving pairing data, writing, full decode.
    - This would require an equivalent function to Crypt(Un)ProtectData to encrypt the pairing data before writing to host partition on sensor.


### TODOs:

- change the identities used
- host partition
    - how to wrap / unwrap pairing data
        - CryptUnprotectData and CryptProtectData, so no easy decoding without Windows
        - mimic the funcitons wrapping / unwrapping data
    - how to store pairing data on sensor
        - missing tags 0, 1 and 5
- where does the common property come from and what is it for
    -> where does the function highLevelSetCommonProptery get its params from
- How does BIOS format the host partition
- What does the 0xa6 command do
- code cleanup
- general cleanup
- (not important) check for update and update


### How to prepare for WinDbg

- delay on startup in register: https://flylib.com/books/en/3.141.1.164/1/


### Abbreviations used:
- tuid = template UID
- SID = windows security identifier
- FW = firmware
- SBL = ?
- MiS = match in sensor


### Acknowledgment

- The driver is based on [Synaptics Tudor Sensors Reverse Engineering Project](https://github.com/Popax21/synaTudor/tree/rev) by Popax21 and his (Driver Relinking Project)[https://github.com/Popax21/synaTudor/tree/relink]
- This blog post: [Reversing a Fingerprint Reader Protocol](https://blog.th0m.as/misc/fingerprint-reversing/) by Thomas Lambertz was very helpful in the beginning.
