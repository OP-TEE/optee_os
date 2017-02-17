# GlobalPlatform Secure Element API Design Document

### BACKGROUND

A `Secure Element (SE)` is a tamper-resistant platform (typically a one chip
secure microcontroller) capable of securely hosting applications and their
confidential and cryptographic data (e.g. key management) in accordance with the
rules and security requirements set forth by a set of well-identified trusted
authorities.

>Simplified speaking, SE is a secure platform that can run application (called
>Applet) on it. In order to communicate with Applet, we need a transport
>interface.

SE can be implemented via one of the following technologies

- Embedded SE (accessed via platform dependent interface, unremovable)
- Universal Integrated Circuit Card (UICC, accessed via SIM interface)
- Advanced secure MicroSD (accessed via sdio/mmc interface)

Which means the physical interface between application processor (AP) and SE can
be quite different.  GlobalPlatform tries to remove this gap and defined a
standard transport API called `Secure Element API` to cover those different
physical transport layer protocols.

SE can be accessed directly in TEE, or indirectly accessed via REE.  In later
case, a **secure channel** is needed to ensure the data stream is not hijacked
in REE. (For secure channel, we may leverage [TZC 400] to create a secure memory
that is not accessible in REE)

![](https://docs.google.com/drawings/d/1fPcNJRVKpJnyzci2KgfVNsOD_y9DVF0Djpu0BzsqOrI/pub?w=796&h=477)

To understand SE API, you need to understand the following terms

- `Trusted Application (TA)`: An application execute in Trust Execution
  Environment (TEE), which is the initiator of SE API.

- `Applet`: Applications that run on smartcard OS. Secure Element API defines
  the method to communicate between host application (in our case, TA) and
  Applet.

- `Service`: A service can be used to retrieve all SE readers available in
  the system, it also provides a service to create a session from TA to a
  specific Reader.

- `Session`: It maintains the connection between TA and a specific Reader.
  Different TAs can have a session opened on the same reader. It is SE manager's
  responsibility to demux the request from different TAs. Upon a session is
  opened by a TA, the card is power-up and ready to accept commands.

- `Reader`: It is an abstraction to describe the transport interface between
  the system and SEs.  You can imagine that a SD card slot is a Reader connected
  with assd. A ril daemon can be another read to talk with UICC cards. Even
  embedded SE should have a (virtual) Reader attached to it.

- `Logical Channel`: It is used by host application (in our case, a TA) to
  communicate with applets on the smartcard. [GlobalPlatform Card Specification]
  defines maximum 20 logical channels, numbered from 0~19.  Channel number 0 is
  so-called `Basic logical channel`, or in short, `Basic channel`. A channel can
  be opened or closed by a host application. It is the smartcard OS's
  responsibility to manage the state of each logical channel. Basic channel is
  always open and cannot be closed. A channel must select an applet, which means
  the command passed through the channel will be processed by the selected
  applet. GlobalPlatform requires a default applet must be selected on basic
  channel after system reset. Host application can select different applet by
  issuing a `SELECT command` on basic channel. Other logical channels (numbered
  1~19) can be opened with or without a given `Application Identifier` (AID). If
  AID is not given, the applet selected on basic channel will be selected on the
  just opened logical channel.

- `MultiSelectable or Non-MultiSelectable`: An applet can be MultiSelectable
  or Non-MultiSelectable. For a Non-MultiSelectable applet, it can only be
  selected by one channel, further `SELECT command` on another channel that is
  targeting to the applet will fail. MultiSelectable applet can be selected by
  multiple channels, the applet can decide maximum number of channels it is
  willing to accept.

### DESIGN

The following figure shows initial architecture of SE API.
![](https://docs.google.com/drawings/d/1wVV0opJmmM9PTptrk8z09_052i-evnjJ8yptu18ZBoU/pub?w=676&h=606)

- `Manager (core/include/tee/se/manager.h)`: This component manages all
  Readers on the system. It should provide reader interface for the Reader
  developers to register their own Reader instance. (In the case of [JavaCard
  Simulator], we should have [PC/SC Passthru Reader] to talk with simulator) It
  also provides an interface for client to get `reader handle` on the system.

- `Reader (core/include/tee/se/reader.h)`: It provides the operations that
  can be applied on a `reader handle`. Just like get reader properties and
  create session to a reader. It’s also responsible for routing an
  operation(open, transmit...etc) to a specific Reader implementation.

- `Protocol (core/include/tee/se/{protocol.h,aid.h,apdu.h})`: This module
  implements the `ISO7816 transport layer` protocol that is used to talk with
  smartcard. It relies on operations provided by Reader to transmit `Application
  Protocol Data Unit` (APDU, refer to [ISO7816-4]) to a specific SE.

- `Session (core/include/tee/se/session.h)`: It provides the operations that
  can be applied on a session. Just like open basic or logical channel, and
  transmit APDU on the session. It relies on protocol layer to create logical,
  basic channel and transmit APDU.

- `Channel (core/include/tee/se/channel.h)`: It provides the operations that
  can be applied on a channel. Like transmit an APDU on the channel, select next
  applet. It relies on protocol module to select AID, and session module to
  transport APDU.

- `Reader interface (core/include/tee/se/reader/interface.h)`: The abstract
  layer used to implement a specific Reader instance, a set of operations need
  to be implemented to support a new Reader.

    - `open()`: Triggered when the first session is connected, the Reader should
      be powered on and reset. Doing initialization. Detect SE is present or not.
    - `close()`: Triggered when the last session to the Reader has been closed.
      The Reader can be powered down in this method.
    - `get_properties()`: Get properties of the Reader. Something like the
      Reader is exclusive to TEE or not. SE is present...etc.
    - `get_atr()`: Get ATR message from the Reader. ATR is defined in ISO7816-3,
      and it is the message report by SE to describe the ability of SE.
    - `transmit()`: Transmit an APDU through the Reader which SE attached to.

### Reference Documents
- [ISO7816-4]
- [GP Secure Element API]
- [PC/SC Lite]
- [PC/SC Passthru Reader]

### How to verify
To test SE API, you need [Modified QEMU] and enhanced [JavaCard simulator].
Please use this [setup script] to setup test environment.

[Modified QEMU]:https://github.com/m943040028/qemu/tree/smart_card_emul
[JavaCard simulator]:https://github.com/m943040028/jcardsim/tree/se_api
[PC/SC Passthru Reader]:https://github.com/m943040028/pcsc_passthru_driver
[PC/SC Lite]:https://pcsclite.alioth.debian.org/
[GlobalPlatform Card Specification]:http://www.globalplatform.org/specificationscard.asp
[GP Secure Element API]: http://www.globalplatform.org/specificationsdevice.asp
[TZC 400]:
http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0504c/index.html
[ISO7816-4]:
http://www.embedx.com/pdfs/ISO_STD_7816/info_isoiec7816-4%7Bed2.0%7Den.pdf
[setup script]:
https://raw.githubusercontent.com/m943040028/optee_os/48fe3bf418bda0047784327cbf72e6613ff547b2/scripts/setup_seapi_optee.sh

