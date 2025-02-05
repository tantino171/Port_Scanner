import socket
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QFormLayout, \
    QMessageBox
from PyQt5.QtCore import Qt
import re


class PortScanner(QWidget):
    def __init__(self):
        super().__init__()

        # CPU çekirdek sayısına göre iş parçacığı sayısını belirleme
        self.max_threads = multiprocessing.cpu_count() * 5  # Dinamik thread ayarı
        self.executor = ThreadPoolExecutor(max_workers=self.max_threads)
        self.is_running = False
        self.current_port = None
        self.scanned_ports = set()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Advanced Port Scanner")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet(""" 
            QWidget { background-color: #2e2e2e; color: white; font-size: 14px; }
            QLabel { color: white; }
            QLineEdit, QTextEdit { background-color: #444444; color: white; border: 1px solid #555555; padding: 5px; }
            QPushButton { background-color: #6c6c6c; color: white; border: 1px solid #555555; padding: 10px; }
            QPushButton:hover { background-color: #8a8a8a; }
        """)

        self.label_ip = QLabel("Target IP or Domain Name:")
        self.entry_ip = QLineEdit()
        self.label_ports = QLabel("Port Range (e.g. 1-65536):")
        self.entry_ports = QLineEdit()
        self.label_speed = QLabel("Scan Speed (1-10, higher is faster):")
        self.entry_speed = QLineEdit()

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self.reset_scan)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout = QVBoxLayout()
        form_layout = QFormLayout()
        form_layout.addRow(self.label_ip, self.entry_ip)
        form_layout.addRow(self.label_ports, self.entry_ports)
        form_layout.addRow(self.label_speed, self.entry_speed)

        layout.addLayout(form_layout)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.reset_button)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.is_running = True

        target = self.entry_ip.text()
        port_range = self.entry_ports.text()
        speed = self.entry_speed.text()

        # Eğer hız değeri boşsa, varsayılan 5 değeri atansın
        if not speed:
            speed = "5"

        # Domain/IP geçerliliği kontrolü
        if not self.is_valid_domain(target):
            self.show_message("Error", "Geçerli bir Domain/IP adresi giriniz (www ile başlayıp .com, .net, .org ile bitmelidir).")
            self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
            return

        try:
            ip = self.resolve_domain_to_ip(target)
        except socket.gaierror:
            self.show_message("Error", "Geçerli bir Domain/IP adresi giriniz.")
            self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
            return

        # Port range kontrolü
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                self.show_message("Error", "Belirlenen degerler araliginda bir deger girin.")
                self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
                return
            if start_port == 0:
                self.show_message("Error", "Port range 1 ile baslar")
                self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
                return
        except ValueError:
            self.show_message("Error", "Belirlenen degerler araliginda bir deger girin.")
            self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
            return

        # Scan speed kontrolü
        try:
            scan_speed = int(speed)
            if scan_speed < 1 or scan_speed > 10:
                self.show_message("Error", "Scan Speed min=1,max=10 verebilirsin")
                self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
                return
            timeout = max(0.5, 2 - (scan_speed / 10) * 1.5)  # Timeout süresini hızla dengele
        except ValueError:
            self.show_message("Error", "Scan Speed min=1,max=10 verebilirsin")
            self.scan_button.setEnabled(True)  # Scan butonunu aktif tutuyoruz
            return

        self.result_text.append(f"Scanning {target} from port {start_port} to {end_port} at speed {scan_speed}...")

        # Sadece TCP portlarını tarama başlatıyoruz
        self.scan_tcp_ports(target, start_port, end_port, timeout)

    def scan_tcp_ports(self, ip, start_port, end_port, timeout):
        for port in range(start_port, end_port + 1):
            if not self.is_running:
                self.current_port = port
                return
            if port in self.scanned_ports:
                continue
            self.executor.submit(self.check_tcp_port, ip, port, timeout)

    def check_tcp_port(self, ip, port, timeout):
        try:
            if not self.is_running:
                return

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service, version = self.get_service_info(ip, port)
                self.update_result(f"TCP Port {port} is open ({service} {version})")
                self.scanned_ports.add(port)
            s.close()
        except:
            pass

    def get_service_info(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            return "Service", banner.strip() if banner else self.get_service_name(port)
        except:
            return self.get_service_name(port), "Unknown Version"

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown Service"

    def update_result(self, message):
        self.result_text.append(message)

    def stop_scan(self):
        self.is_running = False
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def reset_scan(self):
        self.is_running = False
        self.current_port = None
        self.scanned_ports.clear()
        self.entry_ip.clear()
        self.entry_ports.clear()
        self.entry_speed.clear()
        self.result_text.clear()
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def resolve_domain_to_ip(self, domain):
        try:
            socket.inet_aton(domain)  # Doğrudan IP adresi mi kontrol et
            return domain
        except:
            try:
                return socket.gethostbyname(domain)  # Eğer domain ise, IP'ye çevir
            except socket.gaierror:
                raise socket.gaierror

    def show_message(self, title, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(message)
        msg.setWindowTitle(title)
        msg.exec_()

    def show_scan_complete_message(self):
        self.show_message("Scan Complete", "Tarama islemi gerceklestirildi!")

    def is_valid_domain(self, domain):
        """Domain'in geçerliliğini kontrol et (www ile başlayıp, .com, .net, .org ile bitmeli)."""
        regex = r"^www\.[a-zA-Z0-9-]+\.(com|net|org)$"
        if re.match(regex, domain):
            return True
        return False


if __name__ == "__main__":
    app = QApplication([])
    window = PortScanner()
    window.show()
    app.exec_()
