from mini_keycloak.models import SecurityEvent


class EventRepository:
    def __init__(self, session):
        self.session = session

    def add(self, **values):
        event = SecurityEvent(**values)
        self.session.add(event)
        self.session.flush()
        return event
