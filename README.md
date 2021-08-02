# HS-Bot
Windows-only because of WinSock2 but could be ported to linux or macos.

Uses only Zig Standard Library.

Currently this code is able to send simple clienthello to server and recieve tls protocol packets. Nothing more at the moment.\
Made this project just to learn [Zig language](https://ziglang.org/), wich I like a lot.

Should be easily buildable with ZIG 0.8 or later using `zig build` command.\
You can download ZIG compiler by [this link](https://ziglang.org/download/).\
Make sure you added it to PATH before running this command.

If you'd like to develop this thing with me or have any questions feel free to contact me on danyildiabin@ukr.net or submit an issue on this repository.

# Some great resources to learn TLS protocol
[Visual bit-precise representation of TLS handshake and data transport](https://tls.ulfheim.net/).\
[Wiki page](https://en.wikipedia.org/wiki/Transport_Layer_Security), more formal source to understand the protocol.\
[TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246.html) and [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) standard drafts. I find them hard-to-understand but they define how all servers/clients should work.
