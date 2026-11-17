# BACnet/IP Lab: Protocol Analysis with bacnet-stack, YABE, and Wireshark

A small building-automation lab. I ran a simulated BACnet/IP device, browsed and commanded it from a BACnet client, and captured the traffic to see what the protocol actually does on the wire.

## What this lab covers

- Discovering a BACnet device and browsing its objects and properties
- Reading and writing properties, including rejected writes
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

- **Action:** started the capture, then connected YABE so it discovered the device. The capture holds two packets.
- **Who-Is (10.0.0.153 to 10.0.0.255, UDP 47808):** an *unconfirmed* request sent to the subnet broadcast address. The NPDU destination is the global broadcast network (0xFFFF) with a hop count of 255, and the request has no device-instance range, so every BACnet device that receives it is allowed to answer.
- **I-Am (10.0.0.139 to 10.0.0.153):** the server answered within a millisecond. It was sent as a unicast reply straight back to the requester, not as another broadcast. It announces:
  - Device instance **1234**
  - Maximum APDU length accepted: **1476** bytes
  - Segmentation supported: **none** (enumeration value 3)
  - Vendor ID **260** (bacnet-stack)
- **Why Who-Is is unconfirmed:** the APDU type is Unconfirmed-Request, so it has no invoke ID and no acknowledgment of its own. The I-Am is a separate unconfirmed message, not a reply tied to a request ID.
- **Takeaway:** discovery works because anyone can broadcast a Who-Is and every device volunteers its identity. Broadcasts do not cross routers, which is why BBMDs are needed on networks with multiple subnets.

## Capture 2: Reading properties (`captures/02_readproperty.pcap`)

- **Action:** selected Analog Input 1 in YABE. The capture holds one request and its reply.
- **Request:** a **ReadPropertyMultiple** (confirmed, invoke ID **5**) for Analog Input 1, asking for the special property **ALL**. A single request returns every property of the object instead of one request per property.
- **Reply:** a **ComplexACK** with the same invoke ID, carrying **25 properties**. Some of them:

| Property | Value |
|---|---|
| Object_Name | `ANALOG-INPUT-1` |
| Present_Value | 0.0 |
| Units | 98 (percent) |
| Status_Flags | 0000 (no alarm, fault, override, or out-of-service) |
| Event_State | normal |
| Out_Of_Service | FALSE |
| Reliability | no-fault-detected |
| COV_Increment | 1.0 |
| Time_Delay | 0 |

- **Matching reply to request:** the invoke ID. YABE can have several requests outstanding, and each ComplexACK is paired with its request by that number.
- **Takeaway:** the object's name, value, and configuration are all readable by anyone who can capture the traffic.

## Capture 3: Writing properties (`captures/03_writeproperty.pcap`)

The capture holds four request/reply pairs, and two of them are writes.

| Time | Packet | What happened |
|---|---|---|
| 0.000 s | WriteProperty (invoke 6) | Write **Present_Value = 1.0** to Analog Input 1, priority 16 |
| 0.000 s | **Error** | Rejected: error class *property*, code *write-access-denied (40)* |
| 2.836 s | ReadPropertyMultiple (invoke 7) | YABE refreshes the object. Present_Value is still 0.0 and Out_Of_Service is FALSE |
| 9.045 s | WriteProperty (invoke 8) | Write **Time_Delay = 1** to Analog Input 1, priority 16 |
| 9.045 s | **SimpleACK** | Accepted |
| 9.048 s | ReadPropertyMultiple (invoke 9) | Read-back shows **Time_Delay = 1** (it was 0 before the write) |

- **Why the first write failed:** Present_Value of an input object is read-only while Out_Of_Service is FALSE, because the value is supposed to come from the real sensor. The rejection is about the property's rules, not about who sent the request.
- **Why the second write worked:** Time_Delay is a configuration property that accepts writes.
- **Priority:** both requests carry a priority of 16, but priority only has meaning for *commandable* properties such as the Present_Value of an output. It had no effect on this write.
- **Confirmation:** the read-back 3 ms after the SimpleACK is the same check a technician makes after changing a setting, by confirming the device took it.

## Capture 4a: COV subscription (`captures/04a_cov_subscription.pcap`)

Analog Input 1 was subscribed with SubscribeCOV.

- **Subscription parameters:** 120-second lifetime, unconfirmed notifications. YABE renewed the subscription before it expired, so SubscribeCOV repeats.
- **Initial notification:** the server sends the object's current state immediately after every subscribe or renewal.
- **Writes that did not trigger COV:** Deadband, High_Limit, and Time_Delay are configuration properties, not part of what a COV subscription on an analog input reports, so changing them produced no notification.
- **Rejected write:** a write to Event_Detection_Enable was answered with an Error instead of a SimpleACK (error class *property*, code *write-access-denied (40)*, the same rejection as the Present_Value write in capture 3).

## Capture 4b: Polling vs. COV (`captures/04b_poll_vs_cov.pcap`)

![Packets per second: polling vs. COV](screenshots/04_poll_vs_cov_io_graph.png)

*Polling (0-41 s) produces a constant ~2 packets per second. After subscribing with SubscribeCOV, the line drops to zero between events and rises only when I interact with the device.*

**Polling phase (0-41 s)**
- YABE sent a ReadPropertyMultiple for Analog Input 1 about every 1.002 seconds, requesting Present_Value and Status_Flags.
- 42 request/reply pairs in about 41 seconds. Present_Value was 0.0 in every reply, so almost every packet carried no new information.
- The invoke ID counted up to 255 and wrapped to 0, since it is a single byte.

**COV phase (47 s onward)**
- SubscribeCOV for Analog Input 1 at 47.3 s, renewed at 100.1 s.
- Traffic went silent for up to 25 seconds at a time (74.8-99.8 s) with no packets at all.
- Packets in this phase are mostly my own writes and the property refreshes YABE does after each write, not subscription overhead.

**What triggered notifications**
- Present_Value never changed, but Status_Flags did. Each time I toggled **Out_Of_Service**, an UnconfirmedCOVNotification followed within about 10 ms carrying the new flags.
- Writes to Deadband, High_Limit, and Time_Delay produced no notification.

**Takeaway:** polling generates steady traffic whether or not anything changed. COV generates traffic when something does, which matters on networks with thousands of points.

## Security observations

- None of the WriteProperty requests contain a username, password, or any authentication field, and the server accepted them (SimpleACK in capture 3). The writes that failed were rejected because of the property's rules, not because of who sent them.
- Everything is readable in the capture: object IDs, property names, and values travel unencrypted.
- Any device that can reach UDP 47808 on the network could send the same requests. This is why BAS networks are segmented and firewalled, and why exposing BACnet or Modbus devices to the internet is a known risk.
- Writing Out_Of_Service on a point changes what the system reports. It is a useful testing feature for technicians and an obvious tampering target.

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
