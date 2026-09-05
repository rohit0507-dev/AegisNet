from app.capture.packet_capture import PacketCapture


def main():
    print("=" * 70)
    print("                 AEGISNET")
    print(" Real-Time Network Traffic Monitoring and")
    print(" Intrusion Detection System")
    print("=" * 70)

    capture = PacketCapture()

    capture.start()


if __name__ == "__main__":
    main()