### Introduction

I use Wireshark on an almost daily basis to troubleshoot the SIP protocol and have found it an incredibly powerful tool. I've recently been playing with the MMDVM protocol and have used Wireshark for troubleshooting, manually converting the bytes to the appropriate fields. This got tiresome pretty quick, so I created MMDVM-Dissector - a dissector for Wireshark that will parse MMDVM frames and show the relevant fields.

All contributions and feedback are much appreciated.

**This is a work in progress**

### Screenshots

![MMDVM-Dissector](images/MMDVM-Dissector.png?raw=true "MMDVM-Dissector")

### Caveats

* I am **not** a LUA or Wireshark expert, so this may not be perfect code. Use at your own risk.
* Currently MMDVM-dissector will only dissect the MMDVM Headers, not the DMR frames themselves.

### Installation

* Find Wiresharks global configuration directory, by going to `Help > About > Folders`
  * **OSX** - `/Applications/Wireshark.app/Contents/Resources/share/wireshark`
* Copy mmdvm.lua into the directory
* Open init.lua in a text editor and add `dofile(DATA_DIR.."mmdvm.lua")` at the bottom of the file
* Restart / start Wireshark

### Usage

* Open a packet capture (pcap) containing MMDVM packets. You can find an example pcap in this repository. 
* By default anything on port 62030 will be decoded as MMDVM
* If you're using a different port, find a related packet, right click 'Decode As' Set the field to 'UDP Port' and set the 'Current' field to MMDVM

### Licence

This project is licensed under the [Creative Commons CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) licence.

You are free to share and adapt the code as required, however you *must* give appropriate credit and indicate what changes have been made. You must also distribute your adaptation under the same license. Commercial use is prohibited.

### Acknowledgments

Thanks to the creators of the MMDVM protocol -  DL5DI, G4KLX and DG1HT, and anyone else whose contributed to the project.