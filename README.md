# CyberGate — WAF Analysis Intelligence Platform

CyberGate is a premium security analysis dashboard designed to test and visualize the behavior of Web Application Firewalls (WAF), specifically Cloudflare.

## 🚀 Key Logic Features

- **Local Mode (No WAF):** All attack vectors show as `ALLOWED`. This demonstrates how your application remains vulnerable without proper firewall protection.
- **Cloudflare Connected:** When deployed behind Cloudflare, malicious payloads will trigger real 403/429 blocks, which are then detected and shown as `BLOCKED` in the dashboard.
- **Safe Traffic:** Intelligent detection ensures normal user input is always `ALLOWED` and displays a system welcome notification.

---

## ☁️ How to Connect Cloudflare WAF

To test real blocking behavior, follow these steps:

### 1. Host the Platform
Deploy your site to a host that supports custom domains (e.g., Vercel, Netlify, or your own server).

### 2. Connect to Cloudflare
- Add your domain to [Cloudflare](https://www.cloudflare.com/).
- Update your domain's nameservers as instructed by Cloudflare.
- Ensure the "Proxy status" (Orange Cloud) is **Enabled** for your domain.

### 3. Configure WAF Rules
- Navigate to **Security → WAF** in your Cloudflare dashboard.
- Enable **Managed Rules** (specifically the OWASP Core Ruleset).
- *Optional:* Create a **Custom Rule** to block requests containing `attack-test` in the query string if you want to test specific triggers.

### 4. Verify Connection
Refresh CyberGate. The top-right status pill should turn **Green** and say "Cloudflare WAF Connected". You are now ready to test real attack interceptions!

---

## 🛠️ Tech Stack
- **Frontend:** HTML5, Premium Vanilla CSS (Glassmorphism), JavaScript (ES6+).
- **Security:** Real-time Fetch API status monitoring for WAF detection.
- **Design:** Cyber-industrial aesthetic with dark-mode optimization.
"# Cybergate" 
