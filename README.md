# SQD
**Simple Quantar Dissector for Wireshark**

In 2012 a couple of Motorola enthusiasts, Astro Spectra and MattSR reverse engineered the protocol used by the Quantar base station product.  Note that Astro and Quantar are registered trademarks of Motorola, Inc and/or Motorola Trademark Holdings, LLC.

As P25 communications became popular with amateur radio operators, surplus Quantar equipment was pressed into service and the connection of these machines into small networks occured.  A barrier to wide area interconnection was the serial bit synchronous HDLC like protocol used by Motorola.  Enthusiast Astro Spectra published in 2013 a means to link Quantar stations together over IP for P25 digital only operation using off-the-shelf Cisco router hardware. 

Various amateur networks have since been developed based on this Cisco concept using cheap routers to encapsulate the native Quantar V.24 HDLC into frames, using Cisco’s serial tunnelling protocol called STUN (not to be confused with the session traversal utility for NAT).  STUN conveys the encapsulated V.24 over an IP network using TCP.  Methods to do the same thing using UDP usually retain the Cisco router to encapsulate V.24 then convert TCP to UDP by some means, usually software on a Linux platform. As UDP the V.24 frames are 'naked' in that the STUN encapsualtion wrapper is discarded. UDP is often used in multicast mode over a closed network or VPN.

The purpose of this dissector, actually two almost identical dissectors, is to allow convenient viewing of the Quantar V.24 protocol as carried by TCP or UDP.  The port used for Cisco STUN transport is usually 1994 and for UDP the port 23456 or 30000 is common.
To make these dissectors work with Wireshark you need to edit the init.lua file found in the Wireshark install directory in Program Files (Windows).

Set:
```
disable_lua = false 
```  
Then at the very end of the file add:
```
QV24_TCP_SCRIPT_PATH="C:\\Plugins\\"
dofile(QV24_TCP_SCRIPT_PATH.."QV24_TCP.lua")

QV24_UDP_SCRIPT_PATH="C:\\Plugins\\"
dofile(QV24_UDP_SCRIPT_PATH.."QV24_UDP.lua")
```  

Where the path is wherever you’ve put the two dissector files.

If you want to use the QV24 UDP dissector for P25NX V2 trasnport then use:
```
dofile(QV24_UDP_SCRIPT_PATH.."QV24_UDP_P25NX.lua")
```

If you are using Linux, start Wireshark and go to Help -> About Wireshark -> Folders. You need to know the global plugin folder and global configuaration folder. Copy the two dissector files into the global plugin folder. Check init.lua in the global configuration folder and make sure lua is enabled: 
```
disable_lua = false
```
Then run Wireshark and go to Analyze > Enable Protocols and search down until you find the two QV24 entries and tick them.  Don’t untick all the other stuff. Enjoy.

Note that works that make use of Wireshark's API are covered by GPL and therefore this code is provided under GPL.
The author acknowledges the Lua dissector examples published by Devendra Tewari which helped considerably in getting this project started.  Lastly a thank you to the pioneering work of the unknown Motorola hardware and software development engineers who built the superb Quantar platform that has endured for more than 20 years.

