from datetime import datetime


class ResponseManager:

    def __init__(self, simulation_mode=True):

        self.simulation_mode = simulation_mode
        self.active_responses = {}

    def execute(self, source_ip, decision):

        action = decision["action"]

        response = {
            "source_ip": source_ip,
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "mode": (
                "SIMULATION"
                if self.simulation_mode
                else "ACTIVE"
            ),
            "status": "ACTIVE"
        }

        if action == "MONITOR":
            response["duration"] = 0

        elif action == "MONITOR_AND_LOG":
            response["duration"] = 0

        elif action == "TEMPORARY_LIMIT":
            response["duration"] = 30

        elif action == "TEMPORARY_BLOCK":
            response["duration"] = 30

        elif action == "QUARANTINE":
            response["duration"] = 60

        else:
            response["duration"] = 0

        self.active_responses[source_ip] = response

        print()
        print("=" * 70)
        print("             AEGISNET RESPONSE")
        print("=" * 70)

        print(f"Source IP    : {source_ip}")
        print(f"Action       : {action}")
        print(
            f"Duration     : "
            f"{response['duration']} seconds"
        )
        print(f"Mode         : {response['mode']}")

        if self.simulation_mode:
            print("Status       : SIMULATED")
        else:
            print("Status       : ACTIVE")

        print("=" * 70)

        return response

    def restore(self, source_ip):

        if source_ip not in self.active_responses:

            return {
                "source_ip": source_ip,
                "status": "NO_ACTIVE_RESPONSE"
            }

        response = self.active_responses[source_ip]

        response["status"] = "RESTORED"

        response["restore_time"] = (
            datetime.now().isoformat()
        )

        print()
        print("=" * 70)
        print("             AEGISNET RESTORE")
        print("=" * 70)

        print(f"Source IP    : {source_ip}")
        print("Status       : RESTORED")

        print("=" * 70)

        del self.active_responses[source_ip]

        return response

    def get_active_responses(self):

        return self.active_responses.copy()


if __name__ == "__main__":

    manager = ResponseManager(
        simulation_mode=True
    )

    print("=" * 70)
    print("          AEGISNET RESPONSE MANAGER TEST")
    print("=" * 70)

    decision = {
        "action": "TEMPORARY_BLOCK"
    }

    manager.execute(
        "192.168.1.100",
        decision
    )

    print()
    print(
        f"Active responses: "
        f"{len(manager.get_active_responses())}"
    )

    manager.restore(
        "192.168.1.100"
    )

    print()
    print(
        f"Active responses: "
        f"{len(manager.get_active_responses())}"
    )

    print()
    print("=" * 70)
    print("Response manager test completed.")
    print("=" * 70)