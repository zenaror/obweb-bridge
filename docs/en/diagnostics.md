# Diagnostics (Linux)

[Guide index](../../README.md) · [English](../en/diagnostics.md) · [Português (Brasil)](../pt-br/diagnostics.md) · [Español](../es/diagnostics.md)

Before starting, complete the [prerequisites](prerequisites.md). Run commands from the application folder.

With the bridge running, use another terminal:

```sh
sudo .venv/bin/python app/diagnose.py --lan-interface INTERFACE --pcsx2-ip PS2_IP --seconds 45
```

For local Ethernet mode, use the PS2 IP assigned by remote DHCP, visible in the game network settings. The diagnostic monitors only `obw-pcsx2` for that guest IP and reports link counters and protocol metadata without recording payloads, MAC addresses, DNS names, credentials, or IP addresses. To show only the DNS question names in the terminal for this PS2 capture, explicitly add `--show-dns-names`; this does not save them. For a separate LAN client, omit `--pcsx2-ip` and use `--client-ip CLIENT_IP` to limit the capture to that device.

Continue with [Android / ARMSX2](android.md) or [physical PS2](ps2.md). For another computer over LAN, set its network gateway and DNS to the bridge computer and select Sockets in the emulator.

---

Related guides: [Prerequisites: game patch, Python and account](prerequisites.md) · [PCSX2 on the same Windows computer](windows.md) · [PCSX2 on the same Linux computer](linux.md) · [ARMSX2 on Android](android.md) · [Physical PlayStation 2](ps2.md) · [Container on Linux](container.md)

## WSS reconnect diagnostics

In local Ethernet mode, the log counts WSS text messages separately from Ethernet frames. `peer_gone` and `peer_trk` mean that valid JSON text contained the known `kk-peer-gone` or `kk-peer-trk` marker; `other_json` and `non_json` cover other text. These notices are ignored by the relay. Only the first occurrence of each category is logged per session; counters appear every 30 seconds and when the relay ends. Counts restart for each relay session.

Reconnect lines include a local reason and session duration. Where available, numeric WebSocket close codes, HTTP handshake status, or OS error numbers are included. The attempt number and whether guest DHCP has been seen help distinguish failure before game traffic from loss during play. No remote close reasons, JSON contents, packet payloads or account credentials are recorded. After reproducing a problem, use **Copy diagnostic report** and include the approximate time of the failure.
