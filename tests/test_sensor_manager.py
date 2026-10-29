from bk_security.sensors.manager import SensorManager
class S:
    def __init__(self, fail=False): self.fail=fail; self.running=False
    def start(self):
        if self.fail: raise RuntimeError("boom")
        self.running=True
    def stop(self): self.running=False

def test_isolates_sensor_error():
    m=SensorManager({"ok":S(),"bad":S(True)}); m.start_all(); s=m.status()
    assert s["sensors"]["ok"]["status"]=="running"
    assert s["sensors"]["bad"]["status"]=="error"

def test_stop_all():
    m=SensorManager({"a":S()}); m.start_all(); m.stop_all(); assert m.status()["sensors"]["a"]["status"]=="stopped"
