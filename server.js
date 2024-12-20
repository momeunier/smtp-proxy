const express = require("express");
const net = require("net");
const dns = require("dns");
const { promisify } = require("util");
const { exec } = require("child_process");

const app = express();
const port = 3000;

// Promisify DNS lookup functions
const resolveMx = promisify(dns.resolveMx);
const lookup = promisify(dns.lookup);

// Helper function to get MX records and first IP
async function getMxAndIp(domain) {
  const mxRecords = await resolveMx(domain);
  if (!mxRecords || mxRecords.length === 0) {
    throw new Error("No MX records found");
  }

  // Get the highest priority (lowest number) MX record
  const primaryMx = mxRecords.reduce((prev, current) =>
    prev.priority < current.priority ? prev : current
  );

  // Get IP of the MX server
  const { address: ip } = await lookup(primaryMx.exchange);
  return { mxHost: primaryMx.exchange, ip };
}

// TCP connection check (telnet-like approach)
async function checkSmtpTcp(ip) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(5000); // 5 second timeout

    socket.on("connect", () => {
      const duration = Date.now() - startTime;
      socket.destroy();
      resolve(duration);
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timeout"));
    });

    socket.on("error", (err) => {
      reject(err);
    });

    socket.connect(25, ip);
  });
}

// Nmap check approach
async function checkSmtpNmap(ip) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    exec(`nmap -Pn -p 25 ${ip}`, (error, stdout, stderr) => {
      const duration = Date.now() - startTime;
      if (error) {
        reject(error);
        return;
      }

      const isOpen = stdout.includes("25/tcp open");
      if (isOpen) {
        resolve(duration);
      } else {
        reject(new Error("Port 25 is not open"));
      }
    });
  });
}

// Email validation endpoint
app.get("/check", async (req, res) => {
  try {
    const { email, domain } = req.query;
    let targetDomain;

    if (email) {
      targetDomain = email.split("@")[1];
    } else if (domain) {
      targetDomain = domain;
    } else {
      return res.status(400).json({
        success: false,
        error: "Either email or domain parameter is required",
      });
    }

    const { mxHost, ip } = await getMxAndIp(targetDomain);

    // You can switch between TCP and Nmap approaches by commenting/uncommenting
    const duration = await checkSmtpTcp(ip);
    // const duration = await checkSmtpNmap(ip);

    res.json({
      success: true,
      domain: targetDomain,
      mxHost,
      ip,
      connectionTime: duration,
      port: 25,
      status: "open",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.listen(port, () => {
  console.log(
    `SMTP verification service listening at http://localhost:${port}`
  );
});
