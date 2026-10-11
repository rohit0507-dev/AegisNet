"""Run local capture, list adapters, or rebuild the project ML model."""
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="AegisNet network capture")
    parser.add_argument("--interface", help="Adapter index from --list-interfaces, or its name")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--train-model", action="store_true")
    args = parser.parse_args()
    if args.list_interfaces:
        from scapy.all import conf
        print(conf.ifaces)
        return
    if args.train_model:
        from app.ml.anomaly_detector import AnomalyDetector
        AnomalyDetector().train()
        return
    from app.capture.packet_capture import PacketCapture
    from app.capture.runtime import STOP_FILE
    if not os.environ.get("AEGISNET_MANAGED_CAPTURE"):
        STOP_FILE.unlink(missing_ok=True)
    PacketCapture(interface=args.interface).start()


if __name__ == "__main__":
    main()
