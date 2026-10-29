# BK Security V1 architecture

BK Security is an independent security product organized around its own event contract and response policy. Sensors collect endpoint and network observations; the core normalizes, enriches, detects and correlates them before creating SOC incidents.

```text
Network / DNS / Process / Socket / LAN sensors
                    |
             SecurityEvent bus
                    |
     Threat Intel + Behavior + Detection
                    |
       Host / process / destination / time correlation
                    |
             Consolidated incidents
                    |
         AI SOC + MITRE ATT&CK context
                    |
      Policy-controlled Response Engine
                    |
        Authenticated SOC API / WebSocket
                    |
           Dashboard / Electron shell
```

## Product boundaries

- Collection, detection, case management and response are BK-owned modules with BK-owned interfaces.
- `SecuritySensorBridge` accepts callbacks from independently implemented sensors and normalizes them into BK `SecurityEvent` objects.
- Network capture, process/socket sensors and LAN discovery use the same persistent host identity so multi-signal events can correlate across sensors.
- Capture simulation works without packet-capture privileges. Live capture and active LAN discovery are explicit opt-ins.
- AI workers summarize and investigate evidence. The deterministic policy layer controls response actions.
- No destructive response is enabled by default.

## Provenance and dependencies

This source tree does not import or bundle PCYBOX Orbis code and has no runtime dependency on that repository. BK implements its own event model, sensors, detection, incident, API and interface layers. The feature goals are based on the BK product requirements; they are not an Orbis binary or source dependency. Third-party Python and JavaScript packages remain governed by their own licenses.
