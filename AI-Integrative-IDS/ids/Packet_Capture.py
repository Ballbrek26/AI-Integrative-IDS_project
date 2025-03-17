from scapy.all import sniff, IP, TCP
import threading
import queue

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
            )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()