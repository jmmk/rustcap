# Rustcap
Rust wrapper for libpcap

### Developing

#### Windows
By default, rustcap will link with library files from the [WinPcap SDK](https://www.winpcap.org/devel.htm). These files (for both MSVC and MinGW) are included in this repo under the terms of the WinPcap License

MSVC:
- Packet.lib
- wpcap.lib

MinGW:
- libpacket.a
- libwpcap.a

To link with a different version of WinPcap such as [Npcap](https://nmap.org/npcap/), set env var... TODO.
Note that Npcap is subject to a different License; see the documentation for details.

#### *nix
By default, rustcap will link with libpcap found by `pkg-config` or `pcap-config` (usually `/usr/lib/libpcap.dylib` or `/usr/lib/libpcap.so`).
To change this, set env var... TODO


### Runtime

#### Windows
At runtime, rustcap will expect Packet.dll and wpcap.dll to be available in the default DLL search paths (see [https://msdn.microsoft.com/en-us/library/7d83bc18.aspx]()). 
This means in order to run tests and for any end user applications using this code, winpcap and its driver will need to be installed

You can download and install from the following sources:

- [Winpcap](https://www.winpcap.org/install/default.htm)
- [Npcap](https://nmap.org/npcap/) - Look for the link to the installer. Install in Winpcap compatibility mode
- [Winpcap updated to NDIS 6](http://www.win10pcap.org/)

Each download is subject to a different License; see the documentation for details.

#### *nix
libpcap will need to be available on the library path
