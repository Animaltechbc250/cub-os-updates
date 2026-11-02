#!/usr/bin/python3
"""Unprivileged component-update window; package notes are always plain text."""
import json
import sys
from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QMessageBox

HELPER = '/usr/local/libexec/cub-os/cub-component-update'


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Cub OS — Small updates')
        self.resize(700, 540)
        self.approval = None
        self.process = None
        self.output = bytearray()
        self.action = None
        layout = QVBoxLayout(self)
        title = QLabel('Small fixes and component updates')
        title.setStyleSheet('font-size:22px;font-weight:600')
        layout.addWidget(title)
        self.status = QLabel('Check for a signed update. Read its notes before selecting Install.')
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        layout.addWidget(self.notes)
        row = QHBoxLayout()
        self.check = QPushButton('Check for updates')
        self.install = QPushButton('Install update')
        self.rollback = QPushButton('Roll back last update…')
        self.install.setEnabled(False)
        for button in (self.check, self.install, self.rollback):
            row.addWidget(button)
        layout.addLayout(row)
        self.check.clicked.connect(lambda: self.start('online-check'))
        self.install.clicked.connect(lambda: self.start('online-apply'))
        self.rollback.clicked.connect(self.restore)

    def restore(self):
        if QMessageBox.question(self, 'Roll back component update',
                'Restore the previous files from the last component update? Locally modified files will be held for inspection.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel) == QMessageBox.StandardButton.Yes:
            self.start('online-rollback')

    def start(self, action):
        if self.process is not None:
            return
        if action == 'online-apply' and self.approval is None:
            return
        self.action = action
        self.output.clear()
        for b in (self.check, self.install, self.rollback):
            b.setEnabled(False)
        self.status.setText('Checking signed release notes…' if action == 'online-check' else
                            'Working… Keep this window open.')
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self.receive)
        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.error)
        args = [action]
        if action == 'online-apply':
            args += ['--accept', self.approval]
        if action == 'online-check':
            self.process.start(HELPER, args)
        else:
            self.process.start('/usr/bin/pkexec', [HELPER, *args])

    def receive(self):
        self.output.extend(bytes(self.process.readAllStandardOutput()))
        if len(self.output) > 256 * 1024:
            self.output = self.output[-256 * 1024:]
        if self.action != 'online-check':
            lines = self.output.decode('utf8', errors='replace').strip().splitlines()
            if lines:
                self.status.setText(lines[-1])

    def finished(self, code, _status):
        self.receive()
        text = self.output.decode('utf8', errors='replace').strip()
        try:
            if code:
                raise ValueError(text or 'Update command failed. No success was reported.')
            if self.action == 'online-check':
                value = json.loads(text)
                self.approval = None if value.get('installed') or not value.get('can_install', True) else value['approval']
                self.notes.setPlainText(value['title'] + '\n\n' + value['notes'] +
                    '\n\nRestart: ' + value['restart'] + '\nDownload: ' + str(round(value['bytes']/1024**2, 1)) + ' MiB' +
                    ('\n\nFolders this update will create automatically:\n' + '\n'.join('/' + e['path'] + ' (' + format(e['mode'], '04o') + ')' for e in value.get('create_directories', [])) if value.get('create_directories') else ''))
                self.status.setText('This component update is already installed and its files match.' if value.get('installed') else
                                    ('Update cannot be applied: ' + value.get('preflight_message', 'Preflight failed.')) if not value.get('can_install', True) else
                                    'Signed update available. Preflight passed; read the notes, then select Install update.')
            elif self.action == 'online-apply':
                self.status.setText('Update installed and verified. Previous files are retained for rollback.')
                self.approval = None
            else:
                self.status.setText('Previous component files restored and verified.')
                self.approval = None
        except (ValueError, KeyError, TypeError) as error:
            self.status.setText(str(error)[-3000:])
            self.approval = None
        self.process.deleteLater()
        self.process = None
        self.check.setEnabled(True)
        self.rollback.setEnabled(True)
        self.install.setEnabled(self.approval is not None)

    def error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.status.setText('The update helper could not start. No update was installed.')
            self.process.deleteLater()
            self.process = None
            self.approval = None
            self.check.setEnabled(True)
            self.rollback.setEnabled(True)

    def closeEvent(self, event):
        if self.process is not None:
            QMessageBox.information(self, 'Update in progress', 'Keep this window open until the operation finishes.')
            event.ignore()
        else:
            event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    raise SystemExit(app.exec())
