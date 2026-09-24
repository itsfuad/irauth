# Hardware policy

IRAuth's default is intentionally conservative. A webcam being marketed as
"Windows Hello compatible" does not prove Linux exposes the required IR/depth
stream. IRAuth checks what Linux can actually see.

A video device is accepted in strict mode when either:

1. the `/sys/class/video4linux/video*/name` string explicitly identifies
   `IR`, `infrared`, `depth`, or a `3D camera`; or
2. its USB VID:PID appears in `/etc/irauth/hardware.ids` after that exact model
   has been verified on Linux.

Ordinary RGB devices remain visible in `irauthctl hardware` but show
`not accepted` and cannot satisfy setup.

The repository intentionally ships no guessed VID:PID entries. Verified IDs
should be added through reviewed contributions with model name, kernel version,
video-node evidence and an IR-frame test.
