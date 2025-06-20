"""
Point of Sale (POS) System with Wi-Fi Barcode Scanner Integration
Main application file that launches the POS system with network barcode scanning support
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
from datetime import datetime
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
import hashlib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import socket
import webbrowser

# from report import ReportsTab
import pandas as pd
#from tkcalendar import DateEntry
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *

from collections import defaultdict



# Database Models
@dataclass
class Product:
    id: Optional[int] = None
    name: str = ""
    barcode: str = ""
    price: float = 0.0
    stock: int = 0
    category: str = ""


@dataclass
class SaleItem:
    product_id: int
    product_name: str
    price: float
    quantity: int
    subtotal: float


@dataclass
class Sale:
    id: Optional[int] = None
    timestamp: str = ""
    items: List[SaleItem] = None
    subtotal: float = 0.0
    tax: float = 0.0
    discount: float = 0.0
    total: float = 0.0
    cashier: str = ""


# Barcode Server Handler
class BarcodeHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, pos_app=None, **kwargs):
        self.pos_app = pos_app
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests from Barcode to PC app"""
        try:
            # Parse the URL and query parameters
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            # Extract barcode from query parameters
            barcode = None
            if "text" in query_params:
                barcode = query_params["text"][0]
            elif "barcode" in query_params:
                barcode = query_params["barcode"][0]
            elif "data" in query_params:
                barcode = query_params["data"][0]

            if barcode and self.pos_app:
                # Send barcode to POS application
                self.pos_app.handle_network_barcode(barcode)

                # Send success response
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"Barcode received successfully")
            else:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"No barcode data found")

        except Exception as e:
            print(f"Error handling barcode request: {e}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal server error")

    def do_POST(self):
        """Handle POST requests from Barcode to PC app"""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")

            # Try to parse as JSON first
            try:
                data = json.loads(post_data)
                barcode = data.get("text") or data.get("barcode") or data.get("data")
            except json.JSONDecodeError:
                # If not JSON, try URL-encoded data
                parsed_data = urllib.parse.parse_qs(post_data)
                barcode = None
                for key in ["text", "barcode", "data"]:
                    if key in parsed_data:
                        barcode = parsed_data[key][0]
                        break

            if barcode and self.pos_app:
                self.pos_app.handle_network_barcode(barcode)

                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"Barcode received successfully")
            else:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"No barcode data found")

        except Exception as e:
            print(f"Error handling POST barcode request: {e}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal server error")

    def log_message(self, format, *args):
        """Override to reduce console spam"""
        pass


# Database Manager
class DatabaseManager:
    def __init__(self, db_path="pos_system.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Products table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                barcode TEXT UNIQUE,
                price REAL NOT NULL,
                stock INTEGER NOT NULL,
                category TEXT
            )
        """
        )

        # Sales table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                items TEXT NOT NULL,
                subtotal REAL NOT NULL,
                tax REAL NOT NULL,
                discount REAL NOT NULL,
                total REAL NOT NULL,
                cashier TEXT NOT NULL
            )
        """
        )

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """
        )

        # Insert default admin user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
        if cursor.fetchone()[0] == 0:
            admin_password = hashlib.sha256("admin123".encode()).hexdigest()
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            """,
                ("admin", admin_password, "admin"),
            )

        # Insert sample products if table is empty
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] == 0:
            sample_products = [
                ("Apple", "1234567890123", 1.50, 100, "Fruits"),
                ("Banana", "1234567890124", 0.80, 150, "Fruits"),
                ("Bread", "1234567890125", 2.50, 50, "Bakery"),
                ("Milk", "1234567890126", 3.20, 30, "Dairy"),
                ("Eggs", "1234567890127", 4.00, 25, "Dairy"),
                ("Coca Cola", "049000028904", 1.99, 75, "Beverages"),
                ("Pepsi", "012000005100", 1.89, 65, "Beverages"),
            ]
            cursor.executemany(
                """
                INSERT INTO products (name, barcode, price, stock, category)
                VALUES (?, ?, ?, ?, ?)
            """,
                sample_products,
            )

        # Insert a sample sale for today if no sales exist
        cursor.execute("SELECT COUNT(*) FROM sales WHERE DATE(timestamp) = DATE('now')")
        if cursor.fetchone()[0] == 0:
            today_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            sample_sale_items = [
                {"product_id": 1, "name": "Apple", "price": 1.50, "quantity": 2, "subtotal": 3.00},
                {"product_id": 3, "name": "Bread", "price": 2.50, "quantity": 1, "subtotal": 2.50},
            ]
            sample_sale_items_json = json.dumps(sample_sale_items)
            
            sample_subtotal = 5.50
            sample_tax = sample_subtotal * 0.08
            sample_total = sample_subtotal + sample_tax

            cursor.execute(
                """
                INSERT INTO sales (timestamp, items, subtotal, tax, discount, total, cashier)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    today_timestamp,
                    sample_sale_items_json,
                    sample_subtotal,
                    sample_tax,
                    0.0,
                    sample_total,
                    "admin",
                ),
            )
 
        conn.commit()
        conn.close()

    def get_products(self) -> List[Product]:
        """Get all products from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        rows = cursor.fetchall()
        conn.close()

        products = []
        for row in rows:
            products.append(
                Product(
                    id=row[0],
                    name=row[1],
                    barcode=row[2],
                    price=row[3],
                    stock=row[4],
                    category=row[5],
                )
            )
        return products
    

    def get_product_by_barcode(self, barcode: str) -> Optional[Product]:
        """Get product by barcode"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE barcode = ?", (barcode,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return Product(
                id=row[0],
                name=row[1],
                barcode=row[2],
                price=row[3],
                stock=row[4],
                category=row[5],
            )
        return None

    def add_product(self, product: Product) -> bool:
        """Add new product to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO products (name, barcode, price, stock, category)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    product.name,
                    product.barcode,
                    product.price,
                    product.stock,
                    product.category,
                ),
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_product_stock(self, product_id: int, new_stock: int):
        """Update product stock"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE products SET stock = ? WHERE id = ?", (new_stock, product_id)
        )
        conn.commit()
        conn.close()

    def save_sale(self, sale: Sale) -> bool:
        """Save sale to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            items_json = json.dumps([asdict(item) for item in sale.items])
            cursor.execute(
                """
                INSERT INTO sales (timestamp, items, subtotal, tax, discount, total, cashier)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    sale.timestamp,
                    items_json,
                    sale.subtotal,
                    sale.tax,
                    sale.discount,
                    sale.total,
                    sale.cashier,
                ),
            )
            conn.commit()
            conn.close()
            return True
        except:
            return False
        
        
        
    # GETTING SALES 
    def fetch_sales_from_db(self) -> List[Sale]:
        sales_data = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, items, subtotal, tax, discount, total, cashier
                FROM sales
                ORDER BY timestamp DESC
            """)

            rows = cursor.fetchall()
            for row in rows:
                timestamp, items_json, subtotal, tax, discount, total, cashier = row

                # Parse JSON items
                try:
                    items_list = json.loads(items_json)
                    items = [
                        SaleItem(
                            product_id=item.get("product_id", 0),
                            product_name=item.get("name", "Unknown"),
                            price=item.get("price", 0.0),
                            quantity=item.get("quantity", 1),
                            subtotal=item.get("subtotal", item.get("price", 0.0) * item.get("quantity", 1))
                        )
                        for item in items_list
                    ]
                except json.JSONDecodeError:
                    items = []

                sale = Sale(
                    timestamp=timestamp,
                    items=items,
                    subtotal=subtotal,
                    tax=tax,
                    discount=discount,
                    total=total,
                    cashier=cashier
                )

                sales_data.append(sale)

            conn.close()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

        return sales_data
    
    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return role"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute(
            "SELECT role FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash),
        )
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def fetch_sales_by_filters(self, from_date: str, to_date: str, cashier: str) -> List[Sale]:
        sales_data = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            query = """
                SELECT timestamp, items, subtotal, tax, discount, total, cashier
                FROM sales
                WHERE DATE(timestamp) BETWEEN ? AND ?
            """
            params = [from_date, to_date]

            if cashier != "All":
                query += " AND cashier = ?"
                params.append(cashier)
            
            query += " ORDER BY timestamp DESC"

            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                timestamp, items_json, subtotal, tax, discount, total, current_cashier = row
                try:
                    items_list = json.loads(items_json)
                    items = [
                        SaleItem(
                            product_id=item.get("product_id", 0),
                            product_name=item.get("name", "Unknown"),
                            price=item.get("price", 0.0),
                            quantity=item.get("quantity", 1),
                            subtotal=item.get("subtotal", item.get("price", 0.0) * item.get("quantity", 1))
                        )
                        for item in items_list
                    ]
                except json.JSONDecodeError:
                    items = []

                sale = Sale(
                    timestamp=timestamp,
                    items=items,
                    subtotal=subtotal,
                    tax=tax,
                    discount=discount,
                    total=total,
                    cashier=current_cashier
                )
                sales_data.append(sale)

        except sqlite3.Error as e:
            print(f"Database error during filtered sales fetch: {e}")
        return sales_data
    
    
# Login Window
class LoginWindow:
    def __init__(self, master, on_success_callback):
        self.master = master
        self.on_success_callback = on_success_callback
        self.db = DatabaseManager()

        self.window = tk.Toplevel(master)
        self.window.title("POS System Login")
        self.window.geometry("400x250+450+250")
        self.window.resizable(False, False)
        self.window.grab_set()

        # Center the window
        self.window.transient(master)

        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.window, text="POS System Login", font=("Arial", 16, "bold")
        )
        title_label.pack(pady=20)

        # Username
        tk.Label(self.window, text="Username:").pack()
        self.username_entry = tk.Entry(self.window, width=20)
        self.username_entry.pack(pady=5)

        # Password
        tk.Label(self.window, text="Password:").pack()
        self.password_entry = tk.Entry(self.window, width=20, show="*")
        self.password_entry.pack(pady=5)

        # Login button
        login_btn = tk.Button(self.window, text="Login", command=self.login, cursor='hand2')
        login_btn.pack(pady=20)

        # Bind Enter key
        self.window.bind("<Return>", lambda event: self.login())

        # Default credentials info, we will replace this Xantechs and app version.
        info_label = tk.Label(
            self.window, 
            text="(Remove this before exe.)Default: admin / admin123", 
            font=("Arial", 8), 
            fg="gray"
        )
        info_label.pack()

        # Focus on username entry
        self.username_entry.focus()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        role = self.db.authenticate_user(username, password)
        if role:
            self.window.destroy()
            self.on_success_callback(username, role)
        else:
            messagebox.showerror("Error", "Invalid credentials")
            self.password_entry.delete(0, tk.END)


# Network Scanner Configuration Window
class ScannerConfigWindow:
    def __init__(self, master, current_port, current_ip):
        self.master = master
        self.result = None

        self.window = tk.Toplevel(master)
        self.window.title("Wi-Fi Barcode Scanner Setup")
        self.window.geometry("500x400")
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.transient(master)

        self.current_port = current_port
        self.current_ip = current_ip

        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.window, text="Wi-Fi Barcode Scanner Setup", font=("Arial", 16, "bold")
        )
        title_label.pack(pady=10)

        # Instructions
        instructions = """1. Install 'Barcode to PC: Wi-Fi Scanner' app on your phone
2. Connect your phone and computer to the same Wi-Fi network
3. Configure the app with the settings below
4. Start scanning barcodes!"""

        inst_label = tk.Label(self.window, text=instructions, justify=tk.LEFT)
        inst_label.pack(pady=10)

        # Configuration frame
        config_frame = ttk.LabelFrame(self.window, text="Scanner Configuration")
        config_frame.pack(fill=tk.X, padx=20, pady=10)

        # Server IP
        tk.Label(config_frame, text="Server IP Address:192.168.8.100").pack(
            anchor=tk.W, padx=10, pady=5
        )
        self.ip_var = tk.StringVar(value=self.current_ip)
        ip_frame = tk.Frame(config_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Entry(ip_frame, textvariable=self.ip_var, state="readonly", width=20).pack(
            side=tk.LEFT
        )
        tk.Button(ip_frame, text="Copy", command=self.copy_ip).pack(
            side=tk.LEFT, padx=5
        )

        # Server Port
        tk.Label(config_frame, text="Server Port:").pack(anchor=tk.W, padx=10, pady=5)
        port_frame = tk.Frame(config_frame)
        port_frame.pack(fill=tk.X, padx=10, pady=5)

        self.port_var = tk.StringVar(value=str(self.current_port))
        self.port_entry = tk.Entry(port_frame, textvariable=self.port_var, width=10)
        self.port_entry.pack(side=tk.LEFT)
        tk.Button(port_frame, text="Copy", command=self.copy_port).pack(
            side=tk.LEFT, padx=5
        )

        # URL Format
        tk.Label(config_frame, text="URL Format (for manual setup):").pack(
            anchor=tk.W, padx=10, pady=5
        )
        url = f"http://192.168.8.100:8080/?text={{BARCODE}}"
        self.url_var = tk.StringVar(value=url)
        url_frame = tk.Frame(config_frame)
        url_frame.pack(fill=tk.X, padx=10, pady=5)

        url_entry = tk.Entry(
            url_frame, textvariable=self.url_var, state="readonly", width=50
        )
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(url_frame, text="Copy", command=self.copy_url).pack(
            side=tk.LEFT, padx=5
        )

        # QR Code section
        qr_frame = ttk.LabelFrame(self.window, text="Quick Setup")
        qr_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Label(
            qr_frame, text="Use this URL to quickly configure your scanner app:"
        ).pack(pady=5)
        tk.Button(
            qr_frame, text="Open Setup URL in Browser", command=self.open_setup_url
        ).pack(pady=5)

        # Buttons
        btn_frame = tk.Frame(self.window)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Button(btn_frame, text="Apply Changes", command=self.apply_changes).pack(
            side=tk.LEFT, padx=5
        )
        tk.Button(btn_frame, text="Test Connection", command=self.test_connection).pack(
            side=tk.LEFT, padx=5
        )
        tk.Button(btn_frame, text="Close", command=self.close_window).pack(
            side=tk.RIGHT, padx=5
        )

    def copy_ip(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.ip_var.get())
        messagebox.showinfo("Copied", "IP address copied to clipboard")

    def copy_port(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.port_var.get())
        messagebox.showinfo("Copied", "Port copied to clipboard")

    def copy_url(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.url_var.get())
        messagebox.showinfo("Copied", "URL copied to clipboard")

    def open_setup_url(self):
        """Open a simple setup page in the browser"""
        setup_url = f"http://{self.current_ip}:{self.current_port}/setup"
        try:
            webbrowser.open(setup_url)
        except:
            messagebox.showerror(
                "Error", "Could not open browser. Please copy the URL manually."
            )

    def test_connection(self):
        """Test the scanner connection"""
        messagebox.showinfo(
            "Test",
            f"Scanner server is running on {self.current_ip}:{self.current_port}\n\nTry scanning a barcode with your phone app to test the connection.",
        )

    def apply_changes(self):
        """Apply port changes"""
        try:
            new_port = int(self.port_var.get())
            if 1024 <= new_port <= 65535:
                self.result = new_port
                messagebox.showinfo(
                    "Success", "Port updated! Please restart the scanner server."
                )
                self.close_window()
            else:
                messagebox.showerror("Error", "Port must be between 1024 and 65535")
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")

    def close_window(self):
        self.window.destroy()


# Main POS Application
class POSApplication:
    def __init__(self, master):
        self.master = master
        self.db = DatabaseManager()
        self.current_user = None
        self.current_role = None
        self.cart_items = []

        # Network scanner settings
        self.scanner_port = 8080
        self.scanner_server = None
        self.scanner_thread = None
        self.local_ip = self.get_local_ip()

        # Show login first
        self.show_login()

    def get_local_ip(self):
        """Get the local IP address"""
        try:
            # Connect to a remote address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def show_login(self):
        """Show login window"""
        LoginWindow(self.master, self.on_login_success)

    def on_login_success(self, username, role):
        """Called when login is successful"""
        self.current_user = username
        self.current_role = role
        self.setup_main_window()
        self.start_barcode_server()

    def setup_main_window(self):
        """Setup the main POS window"""
        self.master.title(f"POS System - Welcome {self.current_user}")
        self.master.geometry("1200x800")

        # Create menu bar
        self.create_menu()

        # Create main frame
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.create_sales_tab()
        self.create_inventory_tab()
        self.create_reports_tab()
        # self.create_transactions_tab()

        # Status bar
        status_frame = tk.Frame(self.master)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar = tk.Label(
            status_frame,
            text=f"Logged in as: {self.current_user} ({self.current_role})",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Scanner status
        self.scanner_status = tk.Label(
            status_frame,
            text=f"Scanner: {self.local_ip}:{self.scanner_port}",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.E,
            fg="green",
        )
        self.scanner_status.pack(side=tk.RIGHT, padx=5)

    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(
            label="Wi-Fi Scanner Setup", command=self.show_scanner_config
        )
        tools_menu.add_separator()
        tools_menu.add_command(
            label="Restart Scanner Server", command=self.restart_scanner_server
        )

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Scanner Help", command=self.show_scanner_help)

    def show_scanner_config(self):
        """Show scanner configuration window"""
        config_window = ScannerConfigWindow(
            self.master, self.scanner_port, self.local_ip
        )
        self.master.wait_window(config_window.window)

        if config_window.result:
            self.scanner_port = config_window.result
            self.restart_scanner_server()

    def show_scanner_help(self):
        """Show scanner help dialog"""
        help_text = """Wi-Fi Barcode Scanner Help:

1. Download 'Barcode to PC: Wi-Fi Scanner' from your app store
2. Connect your phone and computer to the same Wi-Fi network
3. Open the app and go to Settings
4. Set the server address to: {ip}
5. Set the server port to: {port}
6. Or use this URL format: http://{ip}:{port}/?text={{BARCODE}}
7. Start scanning barcodes!

The scanned barcodes will automatically appear in the product entry field.

Troubleshooting:
- Make sure both devices are on the same network
- Check firewall settings
- Verify the IP address and port
- Try restarting the scanner server from Tools menu""".format(
            ip=self.local_ip, port=self.scanner_port
        )

        help_window = tk.Toplevel(self.master)
        help_window.title("Scanner Help")
        help_window.geometry("500x400")

        text_widget = tk.Text(help_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)

    def start_barcode_server(self):
        """Start the barcode receiving server"""
        try:

            def handler(*args, **kwargs):
                return BarcodeHandler(*args, pos_app=self, **kwargs)

            self.scanner_server = HTTPServer(("0.0.0.0", self.scanner_port), handler)
            self.scanner_thread = threading.Thread(
                target=self.scanner_server.serve_forever, daemon=True
            )
            self.scanner_thread.start()

            print(
                f"Barcode scanner server started on {self.local_ip}:{self.scanner_port}"
            )

        except Exception as e:
            print(f"Failed to start barcode server: {e}")
            messagebox.showerror(
                "Server Error",
                f"Failed to start barcode scanner server on port {self.scanner_port}.\nPlease try a different port.",
            )

    def restart_scanner_server(self):
        """Restart the barcode scanner server"""
        if self.scanner_server:
            self.scanner_server.shutdown()
            self.scanner_server = None

        self.start_barcode_server()
        self.scanner_status.config(text=f"Scanner: {self.local_ip}:{self.scanner_port}")
        messagebox.showinfo(
            "Server Restarted",
            f"Scanner server restarted on {self.local_ip}:{self.scanner_port}",
        )

    def handle_network_barcode(self, barcode):
        """Handle barcode received from network scanner"""
        # Schedule GUI update in main thread
        self.master.after(0, lambda: self.process_network_barcode(barcode))

    def process_network_barcode(self, barcode):
        """Process barcode in main thread"""
        # Switch to sales tab if not already there
        self.notebook.select(0)

        # Set the barcode in the product entry field
        if hasattr(self, "product_entry"):
            self.product_entry.delete(0, tk.END)
            self.product_entry.insert(0, barcode)

            # Flash the entry field to indicate scan received
            self.product_entry.config(bg="lightgreen")
            self.master.after(500, lambda: self.product_entry.config(bg="white"))

            # Automatically try to add to cart
            self.add_product_to_cart()

    def create_sales_tab(self):
        """Create the sales/checkout tab"""
        sales_frame = ttk.Frame(self.notebook)
        self.notebook.add(sales_frame, text="Sales")

        # Left side - Product entry and cart
        left_frame = ttk.Frame(sales_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Product entry section
        entry_frame = ttk.LabelFrame(left_frame, text="Product Entry")
        entry_frame.pack(fill=tk.X, pady=5)

        tk.Label(entry_frame, text="Barcode/Product Name:").pack(anchor=tk.W)
        self.product_entry = tk.Entry(entry_frame, width=30, font=("Arial", 12))
        self.product_entry.pack(pady=5)
        self.product_entry.bind("<Return>", self.add_product_to_cart)

        # Buttons frame
        btn_frame = tk.Frame(entry_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            btn_frame, text="Add to Cart", command=self.add_product_to_cart
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            btn_frame, text="Scanner Setup", command=self.show_scanner_config
        ).pack(side=tk.RIGHT, padx=5)

        # Scanner status in entry frame
        scanner_info = tk.Label(
            entry_frame,
            text=f"📱 Wi-Fi Scanner Ready: {self.local_ip}:{self.scanner_port}",
            font=("Arial", 9),
            fg="green",
        )
        scanner_info.pack(pady=2)

        # Cart section
        cart_frame = ttk.LabelFrame(left_frame, text="Shopping Cart")
        cart_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Cart treeview
        columns = ("Item", "Price", "Qty", "Subtotal")
        self.cart_tree = ttk.Treeview(
            cart_frame, columns=columns, show="headings", height=15
        )

        for col in columns:
            self.cart_tree.heading(col, text=col)
            self.cart_tree.column(col, width=100)

        # Scrollbar for cart
        cart_scrollbar = ttk.Scrollbar(
            cart_frame, orient=tk.VERTICAL, command=self.cart_tree.yview
        )
        self.cart_tree.configure(yscrollcommand=cart_scrollbar.set)

        self.cart_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cart_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Cart buttons
        cart_btn_frame = ttk.Frame(left_frame)
        cart_btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            cart_btn_frame, text="Remove Item", command=self.remove_from_cart
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(cart_btn_frame, text="Clear Cart", command=self.clear_cart).pack(
            side=tk.LEFT, padx=5
        )

        # Right side - Checkout
        right_frame = ttk.Frame(sales_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10, pady=10)

        # Checkout section
        checkout_frame = ttk.LabelFrame(right_frame, text="Checkout")
        checkout_frame.pack(fill=tk.BOTH, expand=True)

        # Total labels
        self.subtotal_label = tk.Label(
            checkout_frame, text="Subtotal: $0.00", font=("Arial", 12)
        )
        self.subtotal_label.pack(pady=5)

        self.tax_label = tk.Label(
            checkout_frame, text="Tax (8%): $0.00", font=("Arial", 12)
        )
        self.tax_label.pack(pady=5)

        self.total_label = tk.Label(
            checkout_frame, text="Total: $0.00", font=("Arial", 14, "bold")
        )
        self.total_label.pack(pady=10)

        # Payment buttons
        ttk.Button(
            checkout_frame, text="Process Payment", command=self.process_payment
        ).pack(pady=10, fill=tk.X)
        ttk.Button(
            checkout_frame, text="Print Receipt", command=self.print_receipt
        ).pack(pady=5, fill=tk.X)

        # Update totals initially
        self.update_totals()
        self.refresh_reports()

    def create_inventory_tab(self):
        """Create the inventory management tab"""
        inventory_frame = ttk.Frame(self.notebook)
        self.notebook.add(inventory_frame, text="Inventory")

        # Top frame for controls
        control_frame = ttk.Frame(inventory_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="Add Product", command=self.add_product).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(control_frame, text="Refresh", command=self.refresh_inventory).pack(
            side=tk.LEFT, padx=5
        )

        # Search frame
        search_frame = ttk.Frame(control_frame)
        search_frame.pack(side=tk.RIGHT)

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = tk.Entry(search_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", self.filter_inventory)

        # Inventory treeview
        inv_columns = ("ID", "Name", "Barcode", "Price", "Stock", "Category")
        self.inv_tree = ttk.Treeview(
            inventory_frame, columns=inv_columns, show="headings"
        )

        for col in inv_columns:
            self.inv_tree.heading(col, text=col)
            self.inv_tree.column(col, width=100)

        # Scrollbar for inventory
        inv_scrollbar = ttk.Scrollbar(
            inventory_frame, orient=tk.VERTICAL, command=self.inv_tree.yview
        )
        self.inv_tree.configure(yscrollcommand=inv_scrollbar.set)

        self.inv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        inv_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)

        # Load initial inventory
        self.refresh_inventory()
        
   

    def create_reports_tab(self):
        reports_tab = ttkb.Frame(self.notebook)
        self.notebook.add(reports_tab, text="Reports")

        # --- Scrollable Canvas Setup ---
        canvas = tk.Canvas(reports_tab, borderwidth=0, highlightthickness=0)
        scrollbar = ttkb.Scrollbar(reports_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttkb.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Optional mousewheel binding
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-1*(event.delta/120)), "units"))

    


        
        

        # ===== Top Filters Frame =====
        filter_frame = ttkb.LabelFrame(scrollable_frame, text="Filter Records", padding=10)
        filter_frame.pack(fill="x", padx=10, pady=5)

        ttkb.Label(filter_frame, text="From:").grid(row=0, column=0, padx=5)
        # from_date = DateEntry(filter_frame, date_pattern='yyyy-mm-dd')
        # from_date.grid(row=0, column=1, padx=5)
        self.begin_date = ttkb.DateEntry(filter_frame, dateformat="%Y-%m-%d")
        self.begin_date.grid(row=0, column=1, padx=5)

        ttkb.Label(filter_frame, text="To:").grid(row=0, column=2, padx=5)
        self.to_date = ttkb.DateEntry(filter_frame, dateformat="%Y-%m-%d")
        self.to_date.grid(row=0, column=3, padx=5)

        ttkb.Label(filter_frame, text="Cashier:").grid(row=0, column=4, padx=5)
        self.cashier_combo = ttkb.Combobox(filter_frame, values=["All", "Cashier1", "Cashier2"])
        self.cashier_combo.current(0)
        self.cashier_combo.grid(row=0, column=5, padx=5)

        self.filter_btn = ttkb.Button(filter_frame, text="Filter", command=self.filter_sales_data)
        self.filter_btn.grid(row=0, column=6, padx=10)

        # ===== Summary Table =====
        table_frame = ttk.Frame(scrollable_frame)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        
        # columns = ("Date", "Cashier", "Items Sold", "Total", "Discount", "Tax", "Net Revenue")
        # tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        # for col in columns:
        #     tree.heading(col, text=col)
        #     tree.column(col, width=100, anchor="center")
        # tree.pack(fill="x")

        # # Example data
        # for i in range(1, 6):
        #     tree.insert("", "end", values=[f"2025-06-{i:02}", "Cashier1", 10+i, 100+i*5, 5, 2, 95+i*3])
        
        # TreeView setup
        columns = ("Date", "Cashier", "Items Sold", "Total", "Discount", "Tax", "Net Revenue")
        self.sales_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)

        for col in columns:
            self.sales_tree.heading(col, text=col)
            self.sales_tree.column(col, width=100, anchor="center")

        self.sales_tree.pack(fill="x")

       # Fetch and populate
        sales_data = self.db.fetch_sales_from_db()
        self.populate_sales_tree(self.sales_tree, sales_data)
        




        # ===== Charts Section =====
        self.chart_frame = ttk.Frame(scrollable_frame)
        self.chart_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.update_report_charts(sales_data, self.chart_frame)
        
        # Call refresh_reports to update sales summary and low stock alerts
        self.refresh_reports()
        
         # ===== Low Stock Section =====
        stock_frame = ttk.LabelFrame(scrollable_frame, text="Low Stock Alert", padding=10)
        stock_frame.pack(fill="x", padx=10, pady=5)

        self.stock_tree = ttk.Treeview(stock_frame, columns=("Product", "Stock"), show="headings", height=4)
        self.stock_tree.heading("Product", text="Product")
        self.stock_tree.heading("Stock", text="Stock")
        self.stock_tree.column("Product", width=200)
        self.stock_tree.column("Stock", width=80, anchor="center")
        self.stock_tree.pack(fill="x")
        
        self.low_stock_label = tk.Label(
            stock_frame, text="Checking inventory...", justify=tk.LEFT
        )
        self.low_stock_label.pack(pady=10)

        # ===== Export Buttons =====
        export_frame = ttk.Frame(scrollable_frame)
        export_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(export_frame, text="Export CSV").pack(side="left", padx=5)
        ttk.Button(export_frame, text="Print Report").pack(side="left", padx=5)

        
              # Sales summary
        sales_frame = ttk.LabelFrame(scrollable_frame, text="Today's Sales Summary")
        sales_frame.pack(fill=tk.X, padx=20, pady=10)

        self.sales_summary_label = tk.Label(
            sales_frame, text="Loading sales data...", justify=tk.LEFT
        )
        self.sales_summary_label.pack(pady=10)  
        self.refresh_reports()



    # def create_reports_tab(self):
    #     """Create the reports tab"""
    #     reports_frame = ttk.Frame(self.notebook)
    #     self.notebook.add(reports_frame, text="Reports")

    #     # Reports content
    #     tk.Label(
    #         reports_frame, text="Sales & Inventory Reports", font=("Arial", 16, "bold")
    #     ).pack(pady=20)

    #     # Sales summary
    #     sales_frame = ttk.LabelFrame(reports_frame, text="Today's Sales Summary")
    #     sales_frame.pack(fill=tk.X, padx=20, pady=10)

    #     self.sales_summary_label = tk.Label(
    #         sales_frame, text="Loading sales data...", justify=tk.LEFT
    #     )
    #     self.sales_summary_label.pack(pady=10)

    #     # Low stock alerts
    #     stock_frame = ttk.LabelFrame(reports_frame, text="Low Stock Alerts")
    #     stock_frame.pack(fill=tk.X, padx=20, pady=10)

    #     self.low_stock_label = tk.Label(
    #         stock_frame, text="Checking inventory...", justify=tk.LEFT
    #     )
    #     self.low_stock_label.pack(pady=10)

    #     # Refresh button
    #     ttk.Button(
    #         reports_frame, text="Refresh Reports", command=self.refresh_reports
    #     ).pack(pady=20)

    #     # Load initial reports
    #     self.refresh_reports()
    

    def filter_inventory(self, event=None):
        """Filter inventory based on search term"""
        search_term = self.search_entry.get().lower()

        # Clear existing items
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)

        # Load and filter products
        products = self.db.get_products()
        for product in products:
            if (
                search_term in product.name.lower()
                or search_term in product.barcode.lower()
                or search_term in product.category.lower()
            ):
                self.inv_tree.insert(
                    "",
                    tk.END,
                    values=(
                        product.id,
                        product.name,
                        product.barcode,
                        f"${product.price:.2f}",
                        product.stock,
                        product.category,
                    ),
                )

    def filter_sales_data(self):
        """Filter sales data based on selected dates and cashier, then update display."""
        from_date = self.begin_date.entry.get()
        to_date = self.to_date.entry.get()
        cashier = self.cashier_combo.get()

        # Basic validation for date format (assuming YYYY-MM-DD from DateEntry)
        try:
            datetime.strptime(from_date, '%Y-%m-%d')
            datetime.strptime(to_date, '%Y-%m-%d')
        except ValueError:
            messagebox.showerror("Date Error", "Please select valid 'From' and 'To' dates.")
            return

        filtered_sales = self.db.fetch_sales_by_filters(from_date, to_date, cashier)
        self.populate_sales_tree(self.sales_tree, filtered_sales)
        
        # Update charts with filtered data
        # The chart_frame is a child of scrollable_frame, which is a child of reports_tab
        # self.sales_tree.master is table_frame
        # self.sales_tree.master.master is scrollable_frame
        # self.sales_tree.master.master.master is reports_tab
        # The chart_frame is directly packed into scrollable_frame
        if self.chart_frame:
            self.update_report_charts(filtered_sales, self.chart_frame)
        else:
            print("Warning: self.chart_frame not found to update charts.")
        
        # Also refresh the sales summary and low stock alerts after filtering
        self.refresh_reports()
        
        # Also refresh the sales summary and low stock alerts after filtering
        self.refresh_reports()


    def refresh_reports(self):
        """Refresh reports data"""
        try:
            # Get today's sales
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()

            today = datetime.now().strftime("%Y-%m-%d")
            cursor.execute(
                "SELECT COUNT(*), SUM(total) FROM sales WHERE DATE(timestamp) = ?",
                (today,),
            )
            sales_data = cursor.fetchone()

            sales_count = sales_data[0] if sales_data[0] else 0
            sales_total = sales_data[1] if sales_data[1] else 0.0

            sales_text = f"Sales Today: {sales_count} transactions\nTotal Revenue: ${sales_total:.2f}"
            self.sales_summary_label.config(text=sales_text)

            conn.close()

            # Check low stock items
            products = self.db.get_products()
            low_stock_items = [p for p in products if p.stock <= 10]

            # Clear existing items in stock_tree
            for item in self.stock_tree.get_children():
                self.stock_tree.delete(item)

            if low_stock_items:
                stock_text = "Low Stock Items:"
                for p in low_stock_items:
                    self.stock_tree.insert("", "end", values=(p.name, p.stock))
                self.low_stock_label.config(text=stock_text)
            else:
                stock_text = "✓ All items have adequate stock levels"
                self.low_stock_label.config(text=stock_text)

        except Exception as e:
            print(f"Error refreshing reports: {e}")

    def add_product_to_cart(self, event=None):
        """Add product to cart by barcode or name"""
        search_term = self.product_entry.get().strip()
        if not search_term:
            return

        # Try to find product by barcode first
        product = self.db.get_product_by_barcode(search_term)

        # If not found by barcode, search by name
        if not product:
            products = self.db.get_products()
            for p in products:
                if search_term.lower() in p.name.lower():
                    product = p
                    break

        if not product:
            messagebox.showerror("Error", f"Product not found: {search_term}")
            return

        if product.stock <= 0:
            messagebox.showerror("Error", f"Product '{product.name}' is out of stock")
            return

        # Ask for quantity
        quantity = simpledialog.askinteger(
            "Quantity",
            f"Enter quantity for {product.name}:",
            initialvalue=1,
            minvalue=1,
            maxvalue=product.stock,
        )
        if not quantity:
            return

        # Check if product already in cart
        existing_item = None
        for i, item in enumerate(self.cart_items):
            if item.product_id == product.id:
                existing_item = i
                break

        if existing_item is not None:
            # Update existing item
            old_qty = self.cart_items[existing_item].quantity
            new_qty = old_qty + quantity

            if new_qty > product.stock:
                messagebox.showerror(
                    "Error",
                    f"Not enough stock. Available: {product.stock}, Requested: {new_qty}",
                )
                return

            self.cart_items[existing_item].quantity = new_qty
            self.cart_items[existing_item].subtotal = product.price * new_qty
        else:
            # Add new item to cart
            sale_item = SaleItem(
                product_id=product.id,
                product_name=product.name,
                price=product.price,
                quantity=quantity,
                subtotal=product.price * quantity,
            )
            self.cart_items.append(sale_item)

        self.update_cart_display()
        self.update_totals()

        # Clear entry and show success
        self.product_entry.delete(0, tk.END)

        # Brief success indication
        original_bg = self.product_entry.cget("bg")
        self.product_entry.config(bg="lightblue")
        self.master.after(200, lambda: self.product_entry.config(bg=original_bg))

    def update_cart_display(self):
        """Update the cart treeview"""
        # Clear existing items
        for item in self.cart_tree.get_children():
            self.cart_tree.delete(item)

        # Add current cart items
        for item in self.cart_items:
            self.cart_tree.insert(
                "",
                tk.END,
                values=(
                    item.product_name,
                    f"${item.price:.2f}",
                    item.quantity,
                    f"${item.subtotal:.2f}",
                ),
            )

    def update_totals(self):
        """Update the total labels"""
        subtotal = sum(item.subtotal for item in self.cart_items)
        tax = subtotal * 0.08  # 8% tax
        total = subtotal + tax

        self.subtotal_label.config(text=f"Subtotal: ${subtotal:.2f}")
        self.tax_label.config(text=f"Tax (8%): ${tax:.2f}")
        self.total_label.config(text=f"Total: ${total:.2f}")

    def remove_from_cart(self):
        """Remove selected item from cart"""
        selection = self.cart_tree.selection()
        if selection:
            index = self.cart_tree.index(selection[0])
            removed_item = self.cart_items[index]
            del self.cart_items[index]
            self.update_cart_display()
            self.update_totals()
            messagebox.showinfo(
                "Removed", f"Removed {removed_item.product_name} from cart"
            )
        else:
            messagebox.showwarning("Warning", "Please select an item to remove")

    def clear_cart(self):
        """Clear all items from cart"""
        if not self.cart_items:
            messagebox.showinfo("Info", "Cart is already empty")
            return

        if messagebox.askyesno("Confirm", "Clear all items from cart?"):
            self.cart_items.clear()
            self.update_cart_display()
            self.update_totals()
            messagebox.showinfo("Cleared", "Cart cleared successfully")

    def process_payment(self):
        """Process the payment and complete sale"""
        if not self.cart_items:
            messagebox.showerror("Error", "Cart is empty")
            return

        subtotal = sum(item.subtotal for item in self.cart_items)
        tax = subtotal * 0.08
        total = subtotal + tax

        # Create sale record
        sale = Sale(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            items=self.cart_items.copy(),
            subtotal=subtotal,
            tax=tax,
            discount=0.0,
            total=total,
            cashier=self.current_user,
        )

        # Save sale
        if self.db.save_sale(sale):
            # Update product stock
            for item in self.cart_items:
                products = self.db.get_products()
                for p in products:
                    if p.id == item.product_id:
                        new_stock = p.stock - item.quantity
                        self.db.update_product_stock(p.id, new_stock)
                        break

            messagebox.showinfo(
                "Success",
                f"Payment processed successfully!\n\nTotal: ${total:.2f}\nItems sold: {len(self.cart_items)}",
            )
            self.clear_cart()
            self.refresh_inventory()  # Refresh inventory to show updated stock
            self.filter_sales_data()  # Update the sales table and charts
        else:
            messagebox.showerror("Error", "Failed to process payment")

    def print_receipt(self):
        """Print receipt (placeholder)"""
        if not self.cart_items:
            messagebox.showinfo("Info", "Cart is empty")
            return

        receipt_text = "=" * 40 + "\n"
        receipt_text += "           SALES RECEIPT\n"
        receipt_text += "=" * 40 + "\n"
        receipt_text += f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        receipt_text += f"Cashier: {self.current_user}\n"
        receipt_text += "-" * 40 + "\n"

        for item in self.cart_items:
            receipt_text += f"{item.product_name}\n"
            receipt_text += (
                f"  {item.quantity} x ${item.price:.2f} = ${item.subtotal:.2f}\n"
            )

        subtotal = sum(item.subtotal for item in self.cart_items)
        tax = subtotal * 0.08
        total = subtotal + tax

        receipt_text += "-" * 40 + "\n"
        receipt_text += f"Subtotal: ${subtotal:.2f}\n"
        receipt_text += f"Tax (8%): ${tax:.2f}\n"
        receipt_text += f"TOTAL: ${total:.2f}\n"
        receipt_text += "=" * 40 + "\n"
        receipt_text += "Thank you for your purchase!\n"
        receipt_text += "Please come again!\n"
        receipt_text += "=" * 40

        # Show receipt in a dialog
        receipt_window = tk.Toplevel(self.master)
        receipt_window.title("Receipt Preview")
        receipt_window.geometry("450x600")
        receipt_window.grab_set()

        # Create frame for text and buttons
        main_frame = tk.Frame(receipt_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Receipt text
        text_widget = tk.Text(main_frame, wrap=tk.WORD, font=("Courier", 10))
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, receipt_text)
        text_widget.config(state=tk.DISABLED)

        # Buttons
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        tk.Button(
            btn_frame,
            text="Copy to Clipboard",
            command=lambda: self.copy_to_clipboard(receipt_text),
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=receipt_window.destroy).pack(
            side=tk.RIGHT, padx=5
        )

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        messagebox.showinfo("Copied", "Receipt copied to clipboard")

    def add_product(self):
        """Add new product to inventory"""
        # Create add product dialog
        dialog = tk.Toplevel(self.master)
        dialog.title("Add New Product")
        dialog.geometry("350x450")
        dialog.grab_set()
        dialog.transient(self.master)

        # Main frame
        main_frame = tk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Title
        tk.Label(main_frame, text="Add New Product", font=("Arial", 14, "bold")).pack(
            pady=10
        )

        # Form fields
        tk.Label(main_frame, text="Product Name:").pack(anchor=tk.W, pady=2)
        name_entry = tk.Entry(main_frame, width=30)
        name_entry.pack(pady=5)

        tk.Label(main_frame, text="Barcode:").pack(anchor=tk.W, pady=2)
        barcode_entry = tk.Entry(main_frame, width=30)
        barcode_entry.pack(pady=5)

        tk.Label(main_frame, text="Price ($):").pack(anchor=tk.W, pady=2)
        price_entry = tk.Entry(main_frame, width=30)
        price_entry.pack(pady=5)

        tk.Label(main_frame, text="Initial Stock:").pack(anchor=tk.W, pady=2)
        stock_entry = tk.Entry(main_frame, width=30)
        stock_entry.pack(pady=5)

        tk.Label(main_frame, text="Category:").pack(anchor=tk.W, pady=2)
        category_entry = tk.Entry(main_frame, width=30)
        category_entry.pack(pady=5)

        def save_product():
            try:
                name = name_entry.get().strip()
                barcode = barcode_entry.get().strip()
                price = float(price_entry.get())
                stock = int(stock_entry.get())
                category = category_entry.get().strip()

                if not name or not barcode:
                    messagebox.showerror("Error", "Name and barcode are required")
                    return

                if price < 0 or stock < 0:
                    messagebox.showerror(
                        "Error", "Price and stock must be non-negative"
                    )
                    return

                product = Product(
                    name=name,
                    barcode=barcode,
                    price=price,
                    stock=stock,
                    category=category or "General",
                )

                if self.db.add_product(product):
                    messagebox.showinfo(
                        "Success", f"Product '{name}' added successfully"
                    )
                    dialog.destroy()
                    self.refresh_inventory()
                else:
                    messagebox.showerror(
                        "Error", "Failed to add product. Barcode might already exist."
                    )
            except ValueError:
                messagebox.showerror(
                    "Error", "Please enter valid numbers for price and stock"
                )

        # Buttons
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=20)

        tk.Button(
            btn_frame,
            text="Save Product",
            command=save_product,
            bg="green",
            fg="white",
            font=("Arial", 10, "bold"),
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(
            side=tk.RIGHT, padx=5
        )

        # Focus on name entry
        name_entry.focus()

    def refresh_inventory(self):
        """Refresh inventory display"""
        # Clear existing items
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)

        # Load products from database
        products = self.db.get_products()
        for product in products:
            # Highlight low stock items
            tags = ()
            if product.stock <= 5:
                tags = ("low_stock",)
            elif product.stock <= 10:
                tags = ("medium_stock",)

            self.inv_tree.insert(
                "",
                tk.END,
                values=(
                    product.id,
                    product.name,
                    product.barcode,
                    f"${product.price:.2f}",
                    product.stock,
                    product.category,
                ),
                tags=tags,
            )

        # Configure tags for stock levels
        self.inv_tree.tag_configure("low_stock", background="#ffcccc")
        self.inv_tree.tag_configure("medium_stock", background="#fff2cc")
        
        # Adding Transactions refresh
    def refresh_transactions(self):
        """Refresh Transaction display"""
        # Clear existing items
        # will change to transaction tree
        for item in self.inv_tree.get_children():
            self.inv_tree.delete(item)

        # Load products from database
        # load transactions from sales tb here
        products = self.db.get_products()
        for product in products:
            # Highlight low stock items
            tags = ()
            if product.stock <= 5:
                tags = ("low_stock",)
            elif product.stock <= 10:
                tags = ("medium_stock",)

            self.inv_tree.insert(
                "",
                tk.END,
                values=(
                    product.id,
                    product.name,
                    product.barcode,
                    f"${product.price:.2f}",
                    product.stock,
                    product.category,
                ),
                tags=tags,
            )

        # Configure tags for stock levels
        self.inv_tree.tag_configure("low_stock", background="#ffcccc")
        self.inv_tree.tag_configure("medium_stock", background="#fff2cc")
        
        
        # Inserting sales data into the table
    def populate_sales_tree(self, tree, sales_data: List[Sale]):
        
        """Populate a Treeview with Sale data."""
        tree.delete(*tree.get_children())  # Clear previous entries

        for sale in sales_data:
            items_sold = sum(item.quantity for item in (sale.items or []))
            net_revenue = sale.subtotal - sale.discount + sale.tax

            tree.insert("", "end", values=(
                sale.timestamp[:10],       # Date
                sale.cashier,              # Cashier
                items_sold,                # Items Sold
                f"${sale.total:.2f}",      # Total
                f"${sale.discount:.2f}",   # Discount
                f"${sale.tax:.2f}",        # Tax
                f"${net_revenue:.2f}"      # Net Revenue
            ))
                
                
        
    def update_report_charts(self, sales_data, chart_frame):
        # === Aggregate Data ===
        daily_totals = defaultdict(float)
        product_quantities = defaultdict(int)

        for sale in sales_data:
            try:
                date_str = sale.timestamp[:10]  # 'YYYY-MM-DD'
                daily_totals[date_str] += sale.total

                for item in sale.items:
                    product_quantities[item.product_name] += item.quantity
            except Exception as e:
                print("Chart aggregation error:", e)
                
                
         # === Bar Chart: Daily Sales ===
        sorted_dates = sorted(daily_totals.keys())
        sorted_totals = [daily_totals[date] for date in sorted_dates]

        fig1, ax1 = plt.subplots(figsize=(4, 3))
        ax1.bar(sorted_dates, sorted_totals, color="#28a745")
        ax1.set_title("Daily Sales")
        ax1.set_ylabel("Total ($)")
        ax1.tick_params(axis='x', rotation=45)
        fig1.tight_layout()

        canvas1 = FigureCanvasTkAgg(fig1, master=chart_frame)
        canvas1.get_tk_widget().grid(row=0, column=0, padx=5, pady=5)

        # === Pie Chart: Top 5 Products ===
        top_products = sorted(product_quantities.items(), key=lambda x: x[1], reverse=True)[:5]

        if top_products:
            labels, quantities = zip(*top_products)
        else:
            labels, quantities = [], []

        fig2, ax2 = plt.subplots(figsize=(4, 3))
        if labels:
            ax2.pie(quantities, labels=labels, autopct="%1.1f%%", startangle=90)
        else:
            ax2.text(0.5, 0.5, "No data", ha="center", va="center")

        ax2.set_title("Top 5 Best Sellers")
        fig2.tight_layout()

        canvas2 = FigureCanvasTkAgg(fig2, master=chart_frame)
        canvas2.get_tk_widget().grid(row=0, column=1, padx=5, pady=5)

    def auto_refresh_reports(self):
        """Automatically refresh reports every second."""
        self.filter_sales_data() # Call the existing filter function
        # Removed automatic refresh scheduling as per requirement

        



# Main execution
def main():
    root = tk.Tk()
    root.withdraw()  # Hide main window initially

    # Set window icon and properties
    root.title("POS System with Wi-Fi Scanner")

    app = POSApplication(root)

    # Show main window only after successful login
    def show_main():
        root.deiconify()
        root.state("zoomed")  # Maximize window on Windows

    # Handle window closing
    def on_closing():
        if app.scanner_server:
            app.scanner_server.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.after(100, show_main)
    root.mainloop()


if __name__ == "__main__":
    main()
