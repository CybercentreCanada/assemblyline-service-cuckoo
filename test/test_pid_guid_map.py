import pytest


class TestProcess:
    @staticmethod
    def test_init():
        from cuckoo.pid_guid_map import Process
        from uuid import UUID
        p = Process(**{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})
        assert p.pid == 1
        assert p.start_time == 0.0
        assert p.end_time == 1.0
        assert p.guid == "{12345678-1234-5678-1234-567812345678}"

        with pytest.raises(ValueError):
            Process("a", 0.0, 1.0, "guid")
        with pytest.raises(ValueError):
            Process(1, 0.0, 1.0, "guid")

    @staticmethod
    def test_eq():
        from cuckoo.pid_guid_map import Process
        p = Process(**{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})
        q = Process(**{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})
        assert p == q

    @staticmethod
    def test_assign_guid():
        from cuckoo.pid_guid_map import Process
        from uuid import UUID
        p = Process(**{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})
        p.assign_guid()
        assert str(UUID(p.guid))


class TestPidGuidMap:
    @staticmethod
    def test_init():
        from cuckoo.pid_guid_map import PidGuidMap, Process
        pgm = PidGuidMap()
        assert pgm.processes == []
        assert pgm.guid_pid_map == {}

        pgm = PidGuidMap([])
        assert pgm.processes == []
        assert pgm.guid_pid_map == {}

        pgm = PidGuidMap([{"pid": 1, "start_time": 0.0, "end_time": 1.0,
                         "guid": "{12345678-1234-5678-1234-567812345678}"}])
        assert pgm.processes[0] == Process(
            **{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})

    @staticmethod
    def test_validate_processes():
        from cuckoo.pid_guid_map import PidGuidMap, Process
        from uuid import UUID
        pgm = PidGuidMap()
        # if not p.guid and p.pid not in pids:
        assert str(UUID(pgm._validate_processes([{"pid": 1, "start_time": 0.0, "end_time": 1.0,
                                                  "guid": None}])[0].guid))

        # else
        assert pgm._validate_processes([{"pid": 2, "start_time": 0.0, "end_time": 1.0,
                                         "guid": "{12345678-1234-5678-1234-567812345678}"}]) == \
            [Process(**{"pid": 2, "start_time": 0.0, "end_time": 1.0,
                        "guid": "{12345678-1234-5678-1234-567812345678}"})]

        # elif p.guid in guids and p.pid in pids:
        pgm.add_process({"pid": 2, "start_time": 0.0, "end_time": 1.0,
                        "guid": "{12345678-1234-5678-1234-567812345678}"})
        assert not len(pgm._validate_processes(
            [{"pid": 2, "start_time": 0.0, "end_time": 1.0,
              "guid": "{12345678-1234-5678-1234-567812345678}"}]))

        # elif p.guid in guids and p.pid not in pids:
        assert not len(
            pgm._validate_processes(
                [{"pid": 3, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"}]))

        # elif p.guid not in guids and p.pid in pids:
        assert pgm._validate_processes([{"pid": 3, "start_time": 1.0, "end_time": 2.0,
                                         "guid": "{87654321-1234-5678-1234-567812345678}"}]) == \
            [Process(**{"pid": 3, "start_time": 1.0, "end_time": 2.0,
                        "guid": "{87654321-1234-5678-1234-567812345678}"})]

    @staticmethod
    def test_handle_pid_match():
        from cuckoo.pid_guid_map import PidGuidMap, Process
        pgm = PidGuidMap()

        # Test where no process is added
        p = Process(1, 1.0, 2.0, "{87654321-1234-5678-1234-567812345678}")
        pgm._handle_pid_match(p)
        assert not len(pgm.processes)

        # Test where duplicate entry
        pgm.add_process({"pid": 1, "start_time": 1.0, "end_time": 2.0,
                        "guid": "{87654321-1234-5678-1234-567812345678}"})
        pgm._handle_pid_match(p)
        assert len(pgm.processes) == 1

        # Test with valid start time
        p = Process(1, 2.0, 3.0, "{87654321-1234-5678-1234-567812345678}")
        pgm._handle_pid_match(p)
        assert len(pgm.processes) == 2

        # Test with valid end time
        p = Process(1, 0.0, 1.0, "{87654321-1234-5678-1234-567812345678}")
        pgm._handle_pid_match(p)
        assert len(pgm.processes) == 3

        # Test invalid entry
        p = Process(1, 0.0, 3.0, "{87654321-1234-5678-1234-567812345678}")
        pgm._handle_pid_match(p)
        assert len(pgm.processes) == 3

    @staticmethod
    def test_add_process():
        from cuckoo.pid_guid_map import PidGuidMap, Process
        pgm = PidGuidMap()
        pgm.add_process({"pid": 1, "start_time": 0.0, "end_time": 1.0,
                         "guid": "{12345678-1234-5678-1234-567812345678}"})
        assert pgm.processes[0] == Process(
            **{"pid": 1, "start_time": 0.0, "end_time": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}"})

    @staticmethod
    def test_get_guid_by_pid_and_time():
        from cuckoo.pid_guid_map import PidGuidMap
        from uuid import UUID
        pgm = PidGuidMap()
        assert pgm.get_guid_by_pid_and_time("blah", 0.0) == ""
        pgm.add_process({"pid": 1, "start_time": 0.0, "end_time": 1.0,
                         "guid": "{12345678-1234-5678-1234-567812345678}"})
        assert pgm.get_guid_by_pid_and_time(1, 0.5) == "{12345678-1234-5678-1234-567812345678}"
