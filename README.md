# 🔐 tunnelforge - Manage Your SSH Tunnels Easily

[![Download tunnelforge](https://img.shields.io/badge/Download-tunnelforge-blue?style=for-the-badge)](https://github.com/TIMUN0224/tunnelforge/releases)

---

## 📖 What is tunnelforge?

tunnelforge helps you create and manage SSH tunnels. It runs in one file with no extra setup. You get a full text-based menu system to control your tunnels and see their status live. You can hide your connections with TLS obfuscation and use a Telegram bot for remote control. It has a kill switch to stop connections quickly if needed.

It supports features like SOCKS5 proxy, port forwarding, and VPN use. You don’t have to install any extra software to run it because tunnelforge has zero dependencies. This tool is useful if you want to secure your internet traffic or connect to private networks safely.

---

## 🖥️ System Requirements

- **Operating System:** Windows 10 or higher, macOS 10.13 or higher, Linux (Ubuntu 18.04+ recommended)
- **Processor:** Any modern 64-bit CPU
- **Memory:** At least 1 GB of RAM free
- **Disk Space:** Around 10 MB for the tunnelforge file
- **Network:** Internet connection for SSH tunnels and Telegram bot usage

No other software or libraries need to be installed to run tunnelforge.

---

## 🚀 Getting Started

This section will guide you step-by-step to download and start tunnelforge on your computer.

---

## ⬇️ Download & Install

1. Click the big blue button at the top or visit this page to download the latest version of tunnelforge:

   [Download tunnelforge Releases](https://github.com/TIMUN0224/tunnelforge/releases)

2. On the releases page, look for a file that matches your computer system:
   - On Windows, choose a file ending with `.exe`.
   - On macOS, choose a `.dmg` or `.app` file.
   - On Linux, look for an executable with no extension or a `.tar.gz` archive.

3. Download the file to a folder you will remember, like your Desktop or Downloads folder.

4. For Windows and macOS:
   - Double-click the downloaded file to run.
   - You may get a security warning since this is a new app; choose to run it anyway.

5. For Linux:
   - Open your terminal.
   - Navigate to the folder where you saved tunnelforge.
   - Run the command `chmod +x tunnelforge` to make it executable.
   - Start it by typing `./tunnelforge` and press Enter.

No installation steps are needed. The file runs directly.

---

## 🔧 How to Use tunnelforge

When you open tunnelforge, it shows a menu (called a TUI - Text User Interface) that looks like this:

- Create and manage SSH tunnels.
- See a live dashboard that updates as your tunnels work.
- Enable TLS obfuscation, so your traffic looks normal and less noticeable.
- Use the Telegram bot to control tunnels from your phone.
- Turn on the kill switch to quickly stop all connections if needed.

You navigate menus with your keyboard arrows and press Enter to select. Here are some typical actions:

### Create a Tunnel

1. Select “Create New Tunnel” in the main menu.
2. Enter the remote server’s IP or domain where you want to connect.
3. Provide your SSH username.
4. Choose the local and remote ports to forward.
5. Select whether to enable SOCKS5 proxy or TLS obfuscation.
6. Save the tunnel.

Your new tunnel will start immediately. You’ll see its status and logs on the live dashboard.

### Manage Tunnels

- Use the dashboard to pause, resume, or stop tunnels.
- View connection logs for debugging or monitoring.
- Access settings to change options like reconnect delays or keep-alive intervals.

### Telegram Bot Control

You can link tunnelforge with your Telegram account:

- Find your bot’s username inside the settings menu.
- Add the bot on Telegram and start chatting.
- Use commands to start or stop tunnels remotely.

This feature helps if you want to manage tunnels while away from your computer.

---

## 🔒 Important Features Explained

- **Full TUI**: This means you use a menu in the terminal window, no need for a mouse or complex commands.
- **Live Dashboard**: Watch your tunnels’ statuses and traffic in real time.
- **TLS Obfuscation**: Makes your SSH traffic look like regular internet traffic. This helps bypass some firewalls.
- **Kill Switch**: An emergency stop button to close all tunnels instantly.
- **Zero Dependencies**: No extra programs are required. Just download the file and run it.
- **Telegram Bot**: Control your tunnels securely from your phone.

---

## ⚙️ Troubleshooting

- **The app won’t start:** Make sure you have permission to run downloaded files. On Windows, check if your antivirus blocks it.
- **Tunnels disconnect often:** Check your internet connection. Try enabling keep-alive settings in the menu.
- **Telegram bot doesn’t respond:** Ensure your bot token and username are correctly set. Also verify your phone has internet access.
- **Ports are in use:** Use different port numbers during tunnel setup or close other apps using those ports.

If problems persist, you can open an issue on the GitHub repository under the "Issues" tab.

---

## 📚 Learn More

The tunnelforge repository includes detailed help files inside the application. Use the help menu or press the key labeled “?” in the TUI for more instructions.

For advanced users, tunnelforge supports features like stunnel integration and SSH key management to improve security.

---

## 🔗 Useful Links

- [Download tunnelforge Releases](https://github.com/TIMUN0224/tunnelforge/releases)
- [GitHub Repository](https://github.com/TIMUN0224/tunnelforge)
- [Issues and Support](https://github.com/TIMUN0224/tunnelforge/issues)

---

## 🛠️ Developer Info (Optional)

This app uses autossh and standard SSH features to manage tunnels. It supports SOCKS5 proxying and integrates stunnel for TLS obfuscation. The Telegram bot uses the Telegram API for remote control. No external dependencies or libraries are needed to run the app.

---

Thank you for choosing tunnelforge for your SSH tunnel needs. Start by downloading it now and follow the steps to secure your connection easily.