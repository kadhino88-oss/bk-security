# Windows capture and Wi-Fi readiness

Updated 2026-10-08. This note separates the capture path that exists today from the work required for coverage of a customer Wi-Fi network and commercial redistribution.

## Current V1 capture path

- The packaged desktop backend starts with capture stopped and does not generate synthetic network packets. The dashboard shows capture mode and counters, reports Npcap/Scapy/elevation readiness, and lets admin/analyst users explicitly select a discovered Npcap interface and start live capture. Wi-Fi selection targets this endpoint's adapter. A separate bounded endpoint Wi-Fi capture passed on 2026-10-12; the packaged dashboard start button remains unverified.
- Packaged production ignores a stale simulation mode, rejects simulation capture and simulation-marked event ingestion, and excludes explicitly simulation-derived events, alerts, and incidents from operational SOC views. The historical rows remain in SQLite; the health endpoint reports excluded counts.
- A local Wi-Fi adapter sees traffic delivered to this endpoint only. Network-wide visibility requires authorized AP/controller/gateway telemetry or mirrored switch traffic and distributed sensors; this V1 does not provide 100 km coverage or automatic network blocking.
- The live path is Npcap/Scapy → `NetworkSensor` → `PacketPipeline` → `SecurityCore` → the existing alert, incident, Threat Family, and investigation paths. The live-capture pipeline normalizes packet metadata; it does not save raw packet files.
- The loopback action sees traffic on this computer only. It is not evidence of visibility into other Wi-Fi clients or a whole routed/switched network.
- The dashboard now recommends a passive SPAN/RSPAN mirror as the first network-wide source and explains the AP/controller/gateway → switch mirror → sensor path. Its Npcap selector still selects one interface on this computer; the UI does not configure or verify switch mirroring.
- `BK_SECURITY_WINDOWS_RESPONSE` remains `0`. Detection and investigation are separate from response execution. Windows BLOCK, ISOLATE, and TERMINATE_PROCESS actions remain disabled under the Phase 6 NO-GO protocol.

## Validation status

- The earlier [Phase 6 live validation](PHASE6_REAL_WORLD_VALIDATION.md) records a successful elevated loopback capture followed through detection, incident/Threat Family, and AI investigation, with the response plan left in dry-run.
- On 2026-10-08, a bounded elevated loopback run captured one UDP test packet at `127.0.0.1:4444`, produced a linked `SUSPICIOUS_NETWORK_BEHAVIOR` alert, incident `tf-ec0dc1185abfa62e505c`, and a valid AI investigation. The response plan stayed dry-run and no adapters were enabled.
- On 2026-10-12, the user ran `scripts/validate_live_wifi_capture.py` in elevated PowerShell. It captured 202 IPv4 packet events involving the endpoint address `192.168.1.121` during a passive five-second window; the temporary database was removed, no test traffic was generated, no raw packets were stored, and response adapters stayed disabled. This proves endpoint event ingestion only; the Phase 6 report records the output and limitations.
- The later Windows test process itself remained non-elevated; it started no capture and the UI reports the missing privilege. The current installed desktop manifest requests administrator elevation. The UI's live-start click path was not separately automated.
- The Wi-Fi adapter was discovered and rendered as a selectable local interface, and the later endpoint capture above passed. Whole-network visibility remains unvalidated.
- On 2026-10-08, the dashboard production build passed with Vite 8.3.3 (16 modules transformed). The local app URL opened to its sign-in screen; the capture panel could not be visually inspected without an authenticated session, and no SPAN/Wi-Fi packet capture or coverage test was run.

## Wi-Fi and whole-network coverage

Coverage of one Windows endpoint and coverage of every client on a Wi-Fi network are different deployment modes. A local endpoint sensor can observe traffic delivered to that host's selected interface. It cannot promise visibility into traffic exchanged only between other clients and the access point.

The selected first infrastructure source is a switch port/VLAN mirror (SPAN, or RSPAN where the switch topology calls for it) delivered to a dedicated wired sensor interface. This is a broadly interoperable passive sensor input and reuses the existing Npcap interface capture path, but actual network-wide support still requires an authorized lab topology and capture validation. A mirror must include the relevant AP uplinks and WLAN/client VLAN traffic. It may omit client-to-client traffic handled inside an AP, and a mirror destination can lose packets when source traffic exceeds its capacity ([Cisco SPAN configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/microswitches/software/releases/15_2_8_e/configuration_guides/nmgmt/b_1528e_nmgmt_cms_cg/configuring-span.html)). Neither a selected adapter nor a running capture proves complete client coverage.

The next capture work must add supported, tested deployment choices:

1. **Endpoint mode:** explicitly select a host's Wi-Fi adapter, test supported Windows/driver combinations, show which host and interface are covered, and keep capture filters and metadata retention bounded.
2. **Infrastructure mode:** validate SPAN/RSPAN as the first packet source, including mirrored AP uplinks/VLANs, source-port completeness, packet drops, and client-to-client blind spots. Later add supported access point/controller/gateway integrations or exported flow/security telemetry where the customer's network requires them. Document the required network configuration and show coverage gaps in the dashboard.
3. **Wireless monitor mode:** treat raw 802.11 capture as an optional hardware/driver capability. Npcap documents that it requires its raw 802.11 support and a compatible adapter/driver; it is not a universal way to observe every network or client.
4. **Verification:** run authorized lab captures against a known topology and traffic generator, prove event-to-alert/incident/Threat Family provenance, measure packet drops and CPU/memory under representative traffic, and separately validate installer upgrade/uninstall behavior.

Npcap's official documentation describes the loopback pseudo-interface and the monitor-mode prerequisites: [Npcap Developer Guide](https://npcap.com/guide/npcap-devguide.html) and [Npcap Users' Guide](https://npcap.com/guide/npcap-users-guide.html).

## Commercial distribution gate

Do not bundle Npcap free/demo with a commercial BK Security installer without resolving its redistribution terms. Npcap's current official pages state that the free/demo release does not normally grant redistribution rights and identify Npcap OEM redistribution licensing for software publishers: [Npcap OEM redistribution license](https://npcap.com/oem/redist). The applicable license, update rights, and customer deployment model must be confirmed before distributing a package that contains Npcap.

Worldwide commercial release also needs product-specific privacy, consent, retention, localization, and customer deployment review for each sales market. This code change does not certify those legal or operational requirements.
