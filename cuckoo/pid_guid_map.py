from logging import getLogger
from typing import List, Dict, Any
from uuid import UUID, uuid4

from assemblyline.common import log as al_log

al_log.init_logging('service.cuckoo.cuckoo_result')
log = getLogger('assemblyline.service.cuckoo.cuckoo_result')


class Process:
    """
    This class represents a process in the lookup table
    """

    def __init__(self, pid: int, start_time: float, end_time: float, guid: str = None) -> None:
        """
        This method initializes a process object
        :param pid: An integer representing a process ID
        :param start_time: An EPOCH time representing when the process was created
        :param end time: An EPOCH time representing when the process was terminated
        :param guid: A GUID representing the process
        :return: None
        """
        # Firs validate that the pid exists and is a valid type
        if pid is None or not isinstance(pid, int):
            raise ValueError(f"{pid} is an invalid pid.")
        self.pid: int = pid
        if start_time > end_time:
            raise ValueError(f"Start time {start_time} cannot be greater than end time {end_time}.")
        self.start_time: float = start_time
        self.end_time: float = end_time
        # If there is no guid assigned, assign one. Otherwise, validate it's value.
        if not guid:
            self.guid = self.assign_guid()
        else:
            self.guid: str = str(UUID(guid))

    def __eq__(self, that) -> bool:
        """
        This method is a helper method that overrides the default eequality funcationality to assist
        with comparing Process objects
        :param self: The process object
        :param that: The process object to be compared
        :return: None
        """
        return self.pid == that.pid and \
            self.start_time == that.start_time and \
            self.end_time == that.end_time and \
            self.guid == that.guid

    def assign_guid(self) -> None:
        """
        This method assigns the GUID for the process object
        :return: None
        """
        self.guid: str = str(uuid4())


class PidGuidMap:
    """
    This class represents the lookup table for Process objects by process ID
    """

    def __init__(self, processes: List[Dict[str, Any]] = []) -> None:
        """
        This method initializes the lookup table
        :param processes: A list of dictionaries that represent Process objects
        :return: None
        """
        self.guid_pid_map: Dict[str, Dict[str, Any]] = {}
        self.processes: List[Process] = self._validate_processes(processes)

    def _validate_processes(self, processes: List[Dict[str, Any]]) -> List[Process]:
        """
        This method validates the list of dictionaries that represent Process objects
        :param processes: A list of dictionaries that represent Process objects
        :return: A list of validated Process objects
        """
        valid_processes: List[Process] = []

        # Grab pids and guids to use for validation
        pids: List[int] = [values["pid"] for values in self.guid_pid_map.values()]
        guids: List[str] = list(self.guid_pid_map.keys())

        for process in processes:
            p = Process(**process)

            if not p.guid and p.pid not in pids:
                # This means we have a unique process that is not yet in the lookup table.
                # Before we add it, assign a GUID to it.
                p.assign_guid()
            elif p.guid in guids and p.pid in pids:
                # We cannot have two items in the table that share process IDs and GUIDs
                raise ValueError(f"{process} is a duplicate entry.")
            elif p.guid in guids and p.pid not in pids:
                # We cannot have two items in the table that share GUIDs
                raise ValueError(f"{process} GUID has already been entered.")
            elif p.guid not in guids and p.pid in pids:
                # We can have two items in the table that share PIDs that don't share GUIDs
                # Further validation is required
                self._handle_pid_match(p)
            else:
                # p.guid and p.guid not in guids and p.pid not in pids
                # We have a unique process that is not yet in the lookup table and has a GUID.
                # Add it!
                pass
            valid_processes.append(p)
        return valid_processes

    def _handle_pid_match(self, process: Process) -> None:
        """
        This method is a deeper step in process validation for processes that share IDs
        :param process: A Process object that shares an ID with another Process object in the lookup table
        :return: None
        """
        valid_entry = False
        # We only care about processes that share process IDs
        processes_with_common_pids = [validated_process for validated_process in self.processes
                                      if validated_process.pid == process.pid]
        for processes_with_common_pid in processes_with_common_pids:
            if processes_with_common_pid.start_time == process.start_time and processes_with_common_pid.end_time == process.end_time:
                # We cannot have multiple processes that share IDs that took place at the same time
                raise ValueError(f"{process} is a duplicate entry.")
            elif process.start_time >= processes_with_common_pid.end_time or process.end_time <= processes_with_common_pid.start_time:
                # We can only have multiple processes that share IDs if they did not take place at the same time
                valid_entry = True
            else:
                # We cannot have multiple processes that share IDs that have overlapping time ranges
                raise ValueError(f"{process} is an invalid entry.")
        if valid_entry:
            self.processes.append(process)

    def add_process(self, process: Dict[str, Any]) -> None:
        """
        This method adds a process to the lookup table
        :param process: The dictionary representation of a Process object to be added to the lookup table
        :return: None
        """
        # Step 1: Validate
        p = self._validate_processes([process])[0]
        # Step 2: Add to lookup table
        self.guid_pid_map[p.guid] = {"pid": p.pid, "start_time": p.start_time, "end_time": p.end_time}
        # Step 3: Add to processes for tracking times
        self.processes.append(p)

    def get_guid_by_pid_and_time(self, pid: int, timestamp: float) -> str:
        """
        This method allows the rtrieval of GUIDs based on a process ID and timestamp
        :param pid: The process ID
        :param timestamp: A timestamp between the creation and termination of a process
        :return: The GUID for the given process ID
        """
        guids: List[str] = [guid for guid, values in self.guid_pid_map.items()
                            if values["pid"] == pid and timestamp <= values["end_time"] and timestamp >= values["start_time"]]

        if not guids:
            log.warning(f"{pid} was not assigned to a process in the table.")
            return ""
        elif len(guids) > 1:
            raise ValueError("Map is invalid.")
        else:
            return guids[0]
