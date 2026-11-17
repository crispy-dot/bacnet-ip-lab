# BACnet/IP Lab: Protocol Analysis with bacnet-stack, YABE, and Wireshark

A small building-automation lab. I ran a simulated BACnet/IP device, browsed and commanded it from a BACnet client, and captured the traffic to see what the protocol actually does on the wire.

## What this lab covers

- Discovering a BACnet device and browsing its objects and properties
- Reading and writing properties, including a rejected write
- Comparing **polling** with **COV (Change of Value)** subscriptions
- What BACnet/IP traffic reveals about security (no authentication, no encryption)
- Troubleshooting a capture-visibility problem with VM networking

## Lab setup

| Role | Tool | Where |
|---|---|---|
| BACnet server (simulated device) | [bacnet-stack](https://github.com/bacnet-stack/bacnet-stack) `bacserv`, device instance 1234 | Ubuntu VM in VirtualBox, bridged adapter (10.0.0.139) |
| BACnet client | YABE (Yet Another BACnet Explorer) | Windows host (10.0.0.153) |
| Packet capture | `tcpdump` on the VM, filter `udp port 47808` | Ubuntu VM |
| Packet analysis | Wireshark | Windows host |

BACnet/IP runs over UDP port 47808 (0xBAC0). Capture files were copied from the VM to the host and opened in Wireshark.

## Repository layout

```
captures/      raw .pcap files, one action per file
screenshots/   Wireshark views and the I/O graph
notes/         troubleshooting log
```

## Capture 1: Discovery (`captures/01_discovery.pcap`)

**Action:** started the capture, then connected YABE so it discovered the device. The capture holds two packets.

| # | Packet | From | To | Type |
|---|---|---|---|---|
| 1 | Who-Is | 10.0.0.153 (YABE) | 10.0.0.255:47808 | Unconfirmed request, broadcast |
| 2 | I-Am | 10.0.0.139 (server) | 10.0.0.153 | Unconfirmed request, unicast |

**Observations**
- The Who-Is is wrapped as a BVLC *Original-Broadcast-NPDU* sent to the subnet broadcast address, and the NPDU's destination network is the global broadcast (0xFFFF). It has no device-range limits, so it asks every device to answer.
- The I-Am came back as a unicast reply. It identifies the sender as **Device 1234** and reports its capabilities: max APDU length 1476, no segmentation support, and a vendor ID of 260.
- Both services are *unconfirmed*: neither has an invoke ID and neither gets an acknowledgment of its own. The I-Am is simply the answer to the broadcast.
- The I-Am was sent back to the source port YABE used for the Who-Is, not to 47808.

**What I learned:** broadcasts stay on the local subnet, which is why a device on another subnet won't answer a Who-Is unless a BBMD forwards it.

## Capture 2: Reading properties (`captures/02_readproperty.pcap`)

**Action:** selected Analog Input 1 in YABE so it read the object's properties.

- **Request:** a **ReadPropertyMultiple** (confirmed service), invoke ID 5, for object **Analog Input 1**, asking for property **ALL**.
- **Reply:** a **ComplexACK** with the same invoke ID (5), about 250 bytes, carrying every property of the object in one packet.

Properties returned include: Object_Name (`ANALOG-INPUT-1`), Object_Type (Analog Input), Present_Value (0.0), Status_Flags (all clear), Event_State (normal), Out_Of_Service (false), COV_Increment (1.0), Time_Delay (0), High_Limit, Low_Limit, and Deadband.

**What I learned:** YABE uses ReadPropertyMultiple instead of plain ReadProperty, which fetches many properties in one round trip. The reply is matched to the request by invoke ID, not by timing.

## Capture 3: Writing properties (`captures/03_writeproperty.pcap`)

The capture holds four request/reply pairs over about 9 seconds.

| Time | Request | Reply |
|---|---|---|
| 0.0 s | **WriteProperty**: Present_Value = 1.0 on Analog Input 1, priority 16 (invoke ID 6) | **Error**: class *property*, code 40 (write-access-denied) |
| 2.8 s | ReadPropertyMultiple, Analog Input 1 (invoke ID 7) | ComplexACK. Time_Delay = 0 |
| 9.0 s | **WriteProperty**: Time_Delay = 1 on Analog Input 1, priority 16 (invoke ID 8) | **SimpleACK** (success) |
| 9.0 s | ReadPropertyMultiple, Analog Input 1 (invoke ID 9) | ComplexACK. Time_Delay = 1 |

**Observations**
- The first write was refused because an Analog Input's Present_Value is read-only while the object is in service. YABE showed no change because the server never accepted it.
- The second write was accepted. The SimpleACK carries no data, only the invoke ID and service, so the follow-up read is the proof: Time_Delay changed from 0 to 1.
- YABE sent priority 16 with both writes. Priority only matters for commandable objects like Analog Outputs, where it selects a slot in the Priority_Array (lower number = higher priority).

**What I learned:** a successful write is only a SimpleACK, so it's worth reading the value back to confirm it. A rejected write comes back as an Error with a class and code, which tells you why.

## Capture 4: Polling vs. COV (`captures/04_cov_vs_poll.pcap`)

![Packets per second: polling vs. COV](screenshots/04_poll_vs_cov_io_graph.png)

*Polling (0-41 s) produces a constant ~2 packets per second. After subscribing with SubscribeCOV, the line drops to zero between events and rises only when I interact with the device.*

**Polling phase (0-41 s)**
- YABE sent a ReadPropertyMultiple for Analog Input 1 about every 1.002 seconds, requesting Present_Value and Status_Flags.
- 42 request/reply pairs in about 41 seconds. Present_Value was 0.0 in every reply, so almost every packet carried no new information.
- The invoke ID counted up to 255 and wrapped to 0, since it is a single byte.

**COV phase (47 s onward)**
- A SubscribeCOV for Analog Input 1 at 47.3 s, with a 120-second lifetime and unconfirmed notifications. YABE renewed it at 100.1 s.
- Right after each subscribe and renewal, the server sent a notification with the current state.
- Traffic went silent for up to 25 seconds at a time (74.8-99.8 s) with no packets at all.
- Packets in this phase are mostly my own writes and the property refreshes YABE does after each write, not subscription overhead.

**What triggered notifications**
- Present_Value never changed, but Status_Flags did. Each time I toggled **Out_Of_Service**, an UnconfirmedCOVNotification followed within about 10 ms carrying the new flags.
- Writes to Deadband, High_Limit, and Time_Delay produced no notification, because they are configuration properties and not part of what a COV subscription on an analog input reports.

**Takeaway:** polling generates steady traffic whether or not anything changed. COV generates traffic when something does, which matters on networks with thousands of points.

## Security observations

- None of the WriteProperty requests contain a username, password, or any authentication field, and the server accepted the valid write (Capture 3, 9.0 s).
- The one rejected write was refused because of how the object works (a read-only property), not because of who sent it. That is property-level behavior, not access control.
- Everything is readable in the captures: object IDs, property names, and values travel unencrypted.
- Any device that can reach UDP 47808 on the network could send the same requests. This is why BAS networks are segmented and firewalled, and why exposing BACnet or Modbus devices to the internet is a known risk.
- Out_Of_Service changes what a point reports. It is a useful testing feature for technicians and an obvious tampering target.

## Troubleshooting log

**1. Command-line client found zero devices.** Running `bacwi` and `bacrp` on the same VM that ran `bacserv` gave "0 devices" and "APDU Timeout." Client and server both want UDP 47808 and discovery relies on broadcast, so they do not work reliably on one machine. YABE on the Windows host worked, because the client and server were separate hosts. (The Who-Is tool in bacnet-stack is `bacwi`; there is no `bacwhois`.)

**2. Wireshark on the host saw no BACnet traffic.** I captured on the Wi-Fi adapter while YABE talked to the VM, and saw nothing. A ping from the host to the VM was also invisible. Traffic between the host and a bridged VM does not pass through the physical adapter, so a capture there misses it. Fix: capture at an endpoint, with `tcpdump` on the VM, then open the files in Wireshark.

```bash
sudo tcpdump -i <interface> -n udp port 47808 -w ~/capture.pcap
```

**Lesson:** a capture only sees traffic that crosses the point where it listens. On a real building network, that means capturing at an endpoint, on a link between devices, or from a switch mirror port or network TAP.

## Useful Wireshark filters

```
bacnet
bacapp.unconfirmed_service == 8     # Who-Is
bacapp.unconfirmed_service == 0     # I-Am
bacapp.confirmed_service == 12      # ReadProperty
bacapp.confirmed_service == 14      # ReadPropertyMultiple
bacapp.confirmed_service == 15      # WriteProperty
bacapp.confirmed_service == 5       # SubscribeCOV
```

Field names can vary by Wireshark version. Right-click a field and choose Apply as Filter if one does not match.

## Next steps

- Script device discovery and reads in Python with BACpypes3
- Add a Modbus lab and compare it with BACnet
- Look at how to segment and monitor a BACnet network
