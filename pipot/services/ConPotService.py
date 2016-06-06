import os
import re
import subprocess

import datetime
from sqlalchemy import Column, String

from database import DeclEnum
from pipot.services.IService import IFileWatchService, IModelIP


class ConnectionType(DeclEnum):
    connection = "connection", "Connection"
    session = "session", "Session"


class ReportConPot(IModelIP):
    __tablename__ = 'report_conpot'

    protocol = Column(String(100))
    conn_type = Column(ConnectionType.db_type())

    def __init__(self, deployment_id, ip, port, protocol, conn_type,
                 timestamp=None):
        super(ReportConPot, self).__init__(deployment_id, ip, port, timestamp)
        self.protocol = protocol
        self.conn_type = conn_type

    def get_message_for_level(self, notification_level):
        message = '%s %s attempt' % (self.protocol, self.conn_type)
        message += '\nPlease take action!' if notification_level > 5 else ''
        return message


class ConPotService(IFileWatchService):
    def __init__(self, collector, config):
        super(ConPotService, self).__init__(collector, config, "conpot.log")
        self.new_regex = re.compile(
            (
                ur'^New ([a-z0-9A-Z]+) (session|connection) from '
                ur'(\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3})(?::(\d{1,5}))?.*$'
            ),
            re.MULTILINE
        )
        """:type : subprocess.Popen"""
        self._ph = None
        """:type : list"""
        self._report_types = ['entries']

    def process_lines(self, lines=None):
        if lines is not None:
            for line in lines:
                line = line[24:]  # Strip off date, it'll get appended later
                if line.startswith("New"):
                    result = self.new_regex.search(line)
                    if result is not None:
                        log_data = {
                            'protocol': result.group(1),
                            'type': result.group(2),
                            'src_host': result.group(3),
                            'src_port': None
                        }
                        try:
                            log_data['src_port'] = result.group(4)
                        except IndexError:
                            pass
                        if log_data['src_port'] is None:
                            log_data['src_port'] = -1
                        # Pass on to collector
                        self._send_to_collector(log_data)

    def run(self):
        super(ConPotService, self).run()
        # Start ConPot
        devnull = open(os.devnull, 'w')
        self._ph = subprocess.Popen(
            ["/usr/local/bin/conpot", "-t", "default"], stdout=devnull,
            stderr=subprocess.STDOUT)

    def stop(self):
        if self._ph is not None:
            try:
                self._ph.kill()
            except OSError:
                pass
            self._ph.wait()

    def get_apt_dependencies(self):
        return ['libmysqlclient-dev', 'libsmi2ldbl', 'smistrip',
                'libxslt1-dev', 'python-dev', 'libevent-dev', 'git',
                'snmp-mibs-downloader']

    def get_pip_dependencies(self):
        return ['conpot']

    def get_ports_used(self):
        return [80, 102, 161, 502, 623, 47808]

    def get_notification_levels(self):
        return range(1, 10)

    def get_notification_level(self, storage_row):
        if storage_row.protocol == 'S7' or storage_row.protocol == 's7comm':
            return 8
        if storage_row.protocol.lower() == 'modbus':
            return 6
        if storage_row.protocol == 'snmp':
            return 4
        if storage_row.protocol == 'http':
            return 2
        return 1

    def get_used_table_names(self):
        return {ReportConPot.__tablename__: ReportConPot}

    def create_storage_row(self, deployment_id, data, timestamp):
        return ReportConPot(
            deployment_id, data['src_host'], data['src_port'],
            data['protocol'], ConnectionType.from_string(data['type']),
            timestamp)

    def get_report_types(self):
        return self._report_types

    def get_data_for_type(self, report_type, **kwargs):
        if report_type == 'entries':
            days = kwargs.pop('time', 7)
            timestamp = datetime.datetime.utcnow() - datetime.timedelta(
                days=days)
            print(timestamp)
            return ReportConPot.query.filter(
                ReportConPot.timestamp >= timestamp).order_by(
                ReportConPot.timestamp.desc()).all()
        return {}

    def get_data_for_type_default_args(self, report_type):
        if report_type == 'entries':
            return {'time': 30}
        return {}

    def get_template_for_type(self, report_type):
        if report_type == 'entries':
            return '<table><thead><tr><th>ID</th><th>Timestamp</th>' \
                   '<th>IP:port</th><th>Protocol</th><th>Connection ' \
                   'type</th></tr></thead><tbody>' \
                   '{% for entry in entries %}<tr><td>{{ entry.id }}</td>' \
                   '<td>{{ entry.timestamp }}</td><td>{{ entry.ip}}:' \
                   '{{ entry.port }}</td><td>{{ entry.protocol }}</td>' \
                   '<td>{{ entry.conn_type.value }}</td></tr>' \
                   '{% else %}<tr><td colspan="4">No entries for this ' \
                   'timespan</td></tr>{% endfor %}</tbody></table>'
        return ''

    def get_template_arguments(self, report_type, initial_data):
        if report_type == 'entries':
            return {
                'entries': initial_data
            }
        return {}
