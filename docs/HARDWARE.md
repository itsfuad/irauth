# Hardware policy

IRAuth's default is intentionally conservative. A webcam being marketed as
"Windows Hello compatible" does not prove Linux exposes the required IR/depth
stream. IRAuth checks what Linux can actually see.

A video device is accepted in strict mode when either:

1. the `/sys/class/video4linux/video*/name` string explicitly identifies
   `IR`, `infrared`, `depth`, or a `3D camera`; or
2. its exact USB **VID:PID + interface number** appears in
   `/etc/irauth/hardware.ids` after that interface has been verified to carry an
   IR/depth stream on Linux.

The allow-list format is `VID:PID@IFACE`, for example `1234:abcd@02`. IRAuth
deliberately does not accept a bare VID:PID: integrated camera modules commonly
put RGB and IR UVC interfaces under the same USB device, so a device-wide match
could accidentally authorize the RGB stream.

Ordinary RGB devices remain visible in `irauthctl hardware` but show
`not accepted` and cannot satisfy setup.

The repository intentionally ships no guessed selectors. Verified selectors
should be added through reviewed contributions with model name, kernel version,
video-node evidence, USB interface evidence and an IR-frame test.

IRAuth also validates the configured backend path at runtime. It is not enough
for an IR camera merely to be present: Howdy's exact `device_path` must resolve
to one of the strict nodes for each authentication ceremony.
