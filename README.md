# IPHunter  
**Simple IP Hunter for Android Devices in C**

A lightweight CLI tool that monitors IP address changes on Android devices by toggling airplane mode. Designed for network testing and automation scenarios.

---

## 🔍 Overview  
IPHunter automates IP address renewal by:
- Toggling airplane mode via root commands
- Monitoring active network interfaces
- Supporting regex-based target IP filtering
- Optional daemon mode with logging
- Customizable check intervals

---

## 📦 Requirements  
- Android device with root access (requires `su`)
- `ip` command-line utility (part of `iproute2`)
- POSIX-compliant environment
- C compiler (e.g., GCC) for building from source

---

## 🛠️ Installation  
1. **Compile from source**:
   ```bash
   ./build.sh
   ```
2. **Move binary to system path**:
   ```bash
   su -c "mv iphunter /system/bin/"
   ```

---

## 🚀 Usage  
```bash
# Normal mode with 5-second interval and IP targets
iphunter 5 "10.21.*;192.168.*"

# Daemon mode with 15-second interval and regex targets
iphunter -d 15 "10.2[1-3].*;192.168.[0-9]+"
```

**Options**:
- `-d`: Run as background daemon
- `-h/--help`: Show usage instructions

**Output**:
- Logs IP changes, target matches, and network status
- Stores logs in `/data/local/tmp/iphunter.log` (daemon mode)

---

## 📄 License  
This project uses the [MIT License](https://opensource.org/licenses/MIT). See full details in the [LICENSE](LICENSE) file.

---

## 🤝 Contributing  
Contributions are welcome! Fork the repo and submit pull requests for:
- New features (e.g., WiFi-only mode)
- Performance improvements
- Documentation enhancements

---

## 📝 Notes  
- Ensure proper permissions for `/data/local/tmp`
- Network readiness timeout: 60 seconds
- Uses POSIX signals and regex libraries

## Credits
- Deepseek R1
- Qwen3
