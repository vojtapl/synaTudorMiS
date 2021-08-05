# Usage of the driver script
## Dependencies
You'll need:
* python3
* cryptography
* pyusb
* matplotlib

## Invocation
The script needs to be run as `root` to be able to access the sensor. You can then invoke it like this:
```shell
sudo python <path to repo>/pydrv/driver.py <arguments> <communication mode> <communication arguments>
```

Argument | Description
--- | ---
-v | Increases the log level
-q | Decreases the log level
\<communication mode\> | How to communicate with the sensor. Currently only `usb` is defined
--vid | The VID of the sensor. Defaults to 0x06cb
--pid | The PID of the sensor. Defaults to 0x00be

## Shell
After you start the script, you should be dropped in a shell waiting for user commands. You can get a list of commands via the command `help`, or print help for a specific command via `help <command>`. You can exit at any time using the command `exit`, or using Ctrl+C or Ctrl+D.

## Tutorial
### First invocation
The first step is to check if the sensor gets found and responds to basic commands. You can verify this by just starting the script. If nothing goes wrong, and you see the prompt for commands, nothing should have gone wrong. You can now get sensor info by using the command `info`
```
$ sudo python pydrv/driver.py usb
   INFO  Found sensor on bus 1 device 4
tudor> info
Driver info:
    pairing data: not present
    initialized: no
    in TLS session: no

Sensor info:
    ID: 85c40ad8609a0000
    FW version: 10.1.3223345
    product id: SensorProductId.PROD_ID5
    advanced security: present
    key flag: set
    provision state: SensorProvisionState.PROVISIONED
    config version: 3463.0.27
    WBF parameter: 0x8
```

### Paring the sensor
After that, you should pair the sensor via the command `pair`. The `info` command should now say that pairing data is present.

You can pair the sensor as many times as you want, but it is adviced to pair it once, and then save the pairing data using the command `save_pdata`. The pairing data can be loaded again using `load_pdata`.
```
tudor> pair
   INFO  Pairing sensor...
Successfully paired sensor
tudor> info
Driver info:
    pairing data: present
    initialized: no
    in TLS session: no

Sensor info:
    ID: 85c40ad8609a0000
    FW version: 10.1.3223345
    product id: SensorProductId.PROD_ID5
    advanced security: present
    key flag: set
    provision state: SensorProvisionState.PROVISIONED
    config version: 3463.0.27
    WBF parameter: 0x8
tudor> save_pdata pdata.tpd
Successfully saved pairing data
```
```
tudor> load_pdata pdata.tpd
Successfully loaded pairing data
```

### Initalization
The next step is to initialize the sensor using the command `init`. This is only possible with present pairing data (see previous step). After you're done using the sensor, you can uninitialize it using the command `uninit`, or let the driver do this automatically when you exit.
```
tudor> init     
   INFO  Initializing sensor...
   INFO  Sucessfully initialized sensor
```

### Events
When the sensor is initialized, you can wait for sensor events to occur using the command `wait_event`. It takes a list of event names described below, and returns when either one of the listed events occurs, or it's interrupted using Ctrl+C. Note that if the event's condition is already satisfied when executing the command, the event will be triggered immediately.

Event name | Description
--- | ---
finger_press | A finger is pressed onto the sensor
finger_remove | A finger is removed from the sensor

```
tudor> wait_event finger_press
Event raised: SensorEvent(type=<SensorEventType.FINGER_PRESS: 1>)
```

### Image capture
Now you can capture images using the command `capture_images`. It takes the number of images as an argument, and displays them in new popup windows.
```
tudor> capture_images 1
Waiting for finger to be lifted...
Capturing images...
```

### Enrollment & Authentication
**TODO**