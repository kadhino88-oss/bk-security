from types import SimpleNamespace
from bk_security.core import SecurityCore
from bk_security.sensors.bridge import SecuritySensorBridge
from bk_security.events.adapters import process_to_event

def test_bk_sensor_bridge_reaches_core():
    core=SecurityCore(); bridge=SecuritySensorBridge(core,"host-1")
    pkt=SimpleNamespace(src_ip="10.0.0.2",dst_ip="8.8.8.8",src_port=5000,dst_port=4444,protocol="TCP",size=100,direction="out",pid=4,process_name="powershell.exe")
    bridge.ingest_packet(pkt)
    assert core.alerts
    assert core.alerts[-1].host_id=="host-1"


def test_bridge_rolls_back_started_sensors_after_start_failure():
    class Sensor:
        def __init__(self, fail=False): self.started=False; self.stopped=False; self.fail=fail
        def start(self, callback=None):
            self.started=True
            if self.fail: raise RuntimeError("sensor startup failed")
        def stop(self): self.stopped=True

    first, second = Sensor(), Sensor(fail=True)
    bridge = SecuritySensorBridge(SecurityCore()).attach(packet_sensor=first, device_sensor=second)
    try:
        bridge.start()
    except RuntimeError as exc:
        assert "startup failed" in str(exc)
    else:
        raise AssertionError("failed sensor startup should propagate")
    assert first.started and first.stopped
    assert second.started and second.stopped
    assert not bridge.running

def test_process_event_normalization():
    e=process_to_event({"pid":42,"name":"powershell.exe","exe":"x","cmdline":["powershell"],"ppid":1,"username":"u"})
    assert e.event_type=="endpoint.process"
    assert e.process["pid"]==42
