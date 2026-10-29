from __future__ import annotations
import os
import ipaddress
import time
from typing import Callable
try:
    import psutil
except Exception:
    psutil = None
from .models import PacketObservation

class LivePacketCapture:
    """Optional Scapy/Npcap capture. Import is deferred so simulation works without Scapy."""
    def __init__(self, callback: Callable[[PacketObservation], object], interface: str | None=None,
                 local_ips: set[str] | None=None, bpf_filter: str='ip'):
        self.callback=callback; self.interface=interface; self.local_ips=local_ips or set(); self.bpf_filter=bpf_filter
        self._sniffer=None; self.running=False; self._socket_map={}; self._socket_map_at=0.0

    @staticmethod
    def available():
        if os.name == "nt":
            from ..platform_windows import find_npcap, is_elevated
            if not find_npcap() or not is_elevated():
                return False
        else:
            from ..platforms import current_provider
            if current_provider().capture_prerequisites():
                return False
        try:
            import scapy.all  # noqa
        except Exception:
            return False
        return True

    def _parse(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        if not pkt.haslayer(IP): return None
        ip=pkt[IP]; proto='IP'; sport=dport=None; flags=None
        if pkt.haslayer(TCP):
            proto='TCP'; sport=int(pkt[TCP].sport); dport=int(pkt[TCP].dport); flags=str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            proto='UDP'; sport=int(pkt[UDP].sport); dport=int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP): proto='ICMP'
        direction='local->remote' if ip.src in self.local_ips else ('remote->local' if ip.dst in self.local_ips else 'unknown')
        pid, process_name = self._attribute(ip.src, sport, ip.dst, dport, proto)
        metadata={}
        if pkt.haslayer(DNS) and (sport == 53 or dport == 53):
            dns=pkt[DNS]
            question_section=dns.getfieldval("qd")
            if isinstance(question_section,DNSQR):
                question=question_section
            else:
                try:
                    question=question_section[0] if question_section else None
                except (IndexError,TypeError):
                    question=None
            if not pkt.haslayer(DNSQR):
                question=None
            raw_domain=getattr(question,"qname",b"") if question else b""
            domain=raw_domain.decode("ascii","replace") if isinstance(raw_domain,bytes) else str(raw_domain or "")
            qtype=int(getattr(question,"qtype",1) or 1) if question else 1
            qtype_name={1:"A",5:"CNAME",12:"PTR",15:"MX",16:"TXT",28:"AAAA"}.get(qtype,f"TYPE{qtype}")
            answers=[]
            answer_section=dns.getfieldval("an")
            if isinstance(answer_section,DNSRR):
                records=[]
                record=answer_section
                for _ in range(64):
                    if not isinstance(record,DNSRR):
                        break
                    records.append(record)
                    record=record.payload
            else:
                try:
                    records=list(answer_section or [])
                except TypeError:
                    records=[]
            for record in records[:64]:
                if int(getattr(record,"type",0) or 0) in {1,28} and getattr(record,"rdata",None):
                    answers.append(str(record.rdata))
            metadata["dns"]={
                "domain":domain.lower().rstrip("."),
                "qtype":qtype_name,
                "answers":answers,
                "response":bool(getattr(dns,"qr",0)),
                "transaction_id":int(getattr(dns,"id",0) or 0),
            }
        packet_timestamp = getattr(pkt, "time", None)
        try:
            packet_timestamp = float(packet_timestamp)
        except (TypeError, ValueError):
            packet_timestamp = time.time()
        return PacketObservation(str(ip.src),str(ip.dst),proto,len(pkt),sport,dport,direction,self.interface,
                                 timestamp=packet_timestamp,
                                 pid=pid,process_name=process_name,flags=flags,metadata=metadata)

    def _refresh_socket_map(self):
        if psutil is None or time.monotonic() - self._socket_map_at < 1.0:
            return
        mapping = {}
        try:
            for c in psutil.net_connections(kind='inet'):
                if not c.laddr:
                    continue
                proc_name = None
                if c.pid:
                    try: proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                local = (c.laddr.ip, c.laddr.port)
                remote = (c.raddr.ip, c.raddr.port) if c.raddr else None
                mapping[(local[0], local[1], remote[0], remote[1], str(c.type).split('.')[-1].lower())] = (c.pid, proc_name)
                mapping[(local[0], local[1], None, None, str(c.type).split('.')[-1].lower())] = (c.pid, proc_name)
        except Exception:
            mapping = {}
        self._socket_map, self._socket_map_at = mapping, time.monotonic()

    def _attribute(self, src, sport, dst, dport, proto):
        self._refresh_socket_map()
        key = (src, sport, dst, dport, proto.lower())
        fallback = (src, sport, None, None, proto.lower())
        return self._socket_map.get(key, self._socket_map.get(fallback, (None, None)))

    def start(self):
        if self.running: return
        if not self.available():
            if os.name == "nt":
                from ..platform_windows import find_npcap, is_elevated
                if not find_npcap():
                    raise RuntimeError('Npcap is not installed or was not detected')
                if not is_elevated():
                    raise RuntimeError('Administrator privileges are required for live capture')
            else:
                from ..platforms import current_provider
                reasons = current_provider().capture_prerequisites()
                if reasons:
                    raise RuntimeError('Live capture prerequisites missing: ' + '; '.join(reasons))
            raise RuntimeError('Scapy/Npcap capture unavailable')
        from scapy.all import AsyncSniffer
        self._sniffer=AsyncSniffer(iface=self.interface, filter=self.bpf_filter, prn=self._on_packet, store=False)
        self._sniffer.start(); self.running=True

    def _on_packet(self, pkt):
        obs=self._parse(pkt)
        if obs: self.callback(obs)

    def stop(self):
        if self._sniffer:
            self._sniffer.stop()
        self._sniffer=None; self.running=False; self._socket_map={}; self._socket_map_at=0.0
