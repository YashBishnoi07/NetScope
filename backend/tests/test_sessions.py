from netscope.sessions import SessionManager


def test_session_manager_tracks_sessions() -> None:
    manager = SessionManager()
    created = manager.create(source="simulator", interface="eth0")

    assert created.session_id.startswith("session-")
    assert manager.get(created.session_id).source == "simulator"
    assert manager.stop(created.session_id).state == "stopped"
