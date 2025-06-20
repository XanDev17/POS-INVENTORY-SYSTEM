# 🧾 Python POS System with Wi-Fi Barcode Scanner Integration

A fully-featured, cross-platform Point of Sale (POS) system built using Python and Tkinter — now enhanced with **Wi-Fi barcode scanning** via smartphone apps like [Barcode to PC: Wi-Fi Scanner](https://barcodetopc.com/).

---

## 🚀 Features

### 🔧 Wi-Fi Barcode Scanner Integration
- **HTTP Server**: Listens for barcode data over the network
- **Real-time Processing**: Barcodes instantly appear in the product entry field
- **Auto Switch to Sales Tab**: Automatically switches to Sales view on scan
- **Visual Feedback**: Entry field flashes green when barcode is received
- **Robust Error Handling**: Handles disconnections, timeouts, and invalid data gracefully

### 📱 Scanner Setup & Configuration
- **Setup Window**: Configure IP and port with ease
- **Auto-detection**: Automatically detects local IP address
- **Copy Buttons**: One-click copy of IP, port, and URL
- **Help Guide**: Built-in help and troubleshooting section

### 🛍️ POS Functionality
- **Inventory Management**: Search by name, barcode, or category
- **Low Stock Alerts**: Visual indicators for stock management
- **Sales Reporting**: Daily summaries and low stock logs
- **Receipts**: Clean, printable receipts with copy-to-clipboard functionality

---

## 📲 How to Use with "Barcode to PC: Wi-Fi Scanner"

1. **Install the App** on your phone: [Google Play](https://play.google.com/store/apps/details?id=com.barcodetopc.wifiscanner) | [App Store](https://apps.apple.com/us/app/barcode-to-pc-wifi-scanner/id1281422148)
2. **Ensure Same Wi-Fi Network**: Both PC and phone must be connected to the same Wi-Fi
3. **Launch the POS App** and open `Tools → Wi-Fi Scanner Setup`
4. **Configure the App**: Enter your computer's IP and port (default: `8080`)
5. **Start Scanning**: Barcodes will instantly appear in the POS system!

---

## ⚙️ Alternative Configuration Options

### ✅ Method 1: Automatic Setup
- Use the IP and Port displayed in the setup window
- Format: `http://YOUR_IP:8080/?text=YOUR_BARCODE`

### ✅ Method 2: Manual HTTP Request
- Send a GET request to:  
  `http://<Your_IP>:8080/?text=123456789012`

### ✅ Method 3: JSON POST Request
- Send a POST request with this body:
```json
{ "text": "123456789012" }
