import http from "http";
import crypto from "crypto";
import net from "net";
import dgram from "dgram";
import { WebSocketServer } from "ws";

export const maxDuration = 300;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  const uuid = crypto.randomUUID();
  const host = req.headers.host || "localhost";
  const url = `vless://${uuid}@${host}?security=tls&encryption=none&insecure=0&type=ws&allowInsecure=0#${host}`;
  const html = /*html*/ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${uuid}</title>
</head>
<body>
    <a href="${url}" target="_blank">${url}</a>
</body>
</html>`;
  res.end(html);
});

const wss = new WebSocketServer({ server });

let connectionId = 0;

wss.on("connection", function connection(ws) {
  const id = ++connectionId;
  const startTime = Date.now();
  console.log(`[${id}] WebSocket connected`);

  ws.on("error", (e) => console.error(`[${id}] WebSocket error:`, e));

  let isFirstRequest = true;
  let isFirstResponse = true;
  let command: string | undefined;

  // TCP state
  let conn: net.Socket;
  let connReady = false;
  const pendingData: Buffer[] = [];

  // UDP state
  let udpSocket: dgram.Socket | null = null;

  const handleError = (e: unknown) => {
    console.error(`[${id}] Error:`, e);
    cleanup();
    ws.close();
  };

  const cleanup = () => {
    if (conn && !conn.destroyed) {
      conn.destroy();
    }
    if (udpSocket) {
      udpSocket.close();
      udpSocket = null;
    }
  };

  ws.on("message", async (_data) => {
    try {
      const data = Buffer.isBuffer(_data) ? _data : Buffer.from(_data as ArrayBuffer);
      if (isFirstRequest) {
        isFirstRequest = false;
        const vless = parseVlessRequestPacket(data);
        command = vless.command;

        console.log(`[${id}] -> ${vless.address || "(none)"}:${vless.port} (${vless.command ?? "unknown"})`);

        if (vless.command === "mux" || !vless.command || !vless.address) {
          // TODO: implement Mux.Cool/XUDP framing for UDP FullCone NAT
          console.log(`[${id}] Unsupported command: ${vless.command ?? "unknown"}, closing`);
          ws.close();
          return;
        }

        if (vless.command === "udp") {
          // UDP mode: create a UDP socket and relay packets
          udpSocket = dgram.createSocket(vless.address.includes(":") ? "udp6" : "udp4");

          udpSocket.on("error", handleError);

          udpSocket.on("message", (msg, rinfo) => {
            if (ws.readyState !== ws.OPEN) return;
            let packet: Buffer;
            if (isFirstResponse) {
              isFirstResponse = false;
              packet = Buffer.concat([Buffer.from([vless.version, 0]), msg]);
            } else {
              packet = msg;
            }
            ws.send(packet);
          });

          // Send the first UDP packet
          udpSocket.send(vless.data, vless.port, vless.address);
        } else {
          // TCP mode
          conn = net.connect(vless.port, vless.address);
          conn.on("error", handleError);
          conn.on("data", (data) => {
            if (ws.readyState !== ws.OPEN) return;
            let packet: Buffer;
            if (isFirstResponse) {
              isFirstResponse = false;
              packet = Buffer.concat([Buffer.from([vless.version, 0]), data]);
            } else {
              packet = data;
            }
            ws.send(packet);
          });
          conn.on("end", () => {
            ws.close();
          });

          await new Promise<void>((resolve) => {
            conn.on("ready", () => resolve());
          });

          connReady = true;
          conn.write(vless.data);

          // Flush any messages that arrived while connecting
          for (const pending of pendingData) {
            conn.write(pending);
          }
          pendingData.length = 0;
        }
      } else {
        if (command === "udp") {
          if (udpSocket) {
            udpSocket.send(data, 0, data.length);
          }
        } else {
          // TCP: forward raw data
          if (connReady && conn) {
            conn.write(data);
          } else {
            pendingData.push(data);
          }
        }
      }
    } catch (e) {
      handleError(e);
    }
  });

  ws.on("close", () => {
    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[${id}] WebSocket closed (duration: ${duration}s)`);
    cleanup();
  });
});

export default server;

/**
 * Parse a VLESS request packet.
 * @see https://xtls.github.io/development/protocols/vless.html
 */
function parseVlessRequestPacket(_vlessBuffer: Uint8Array) {
  const vlessBuffer = new Uint8Array(getUnderlyingArrayBuffer(_vlessBuffer));
  if (vlessBuffer.byteLength < 24) throw new Error("invalid buffer");

  const version = vlessBuffer[0]!;
  const uuid = vlessBuffer.subarray(1, 17);

  const protoBufLength = vlessBuffer[17]!;
  const protoBuf = vlessBuffer.subarray(18, 18 + protoBufLength);

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  const command = vlessBuffer[18 + protoBufLength]!;

  const portIndex = 18 + protoBufLength + 1;
  if (portIndex + 2 > vlessBuffer.byteLength) throw new Error("buffer too short for port");

  // port is big-Endian in raw data etc 80 == 0x0050
  const port = new DataView(vlessBuffer.buffer, vlessBuffer.byteOffset + portIndex, 2).getUint16(0, false);

  const addressIndex = portIndex + 2;
  if (addressIndex >= vlessBuffer.byteLength) throw new Error("buffer too short for address type");

  // 1--> ipv4  addressLength =4
  // 2--> domain name
  // 3--> ipv6  addressLength =16
  const addressType = vlessBuffer[addressIndex];
  let addressLength: number;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength)
        throw new Error("buffer too short for IPv4 address");
      addressValue = vlessBuffer.subarray(addressValueIndex, addressValueIndex + addressLength).join(".");
      break;
    case 2:
      if (addressValueIndex >= vlessBuffer.byteLength) throw new Error("buffer too short for domain length");
      addressLength = vlessBuffer[addressValueIndex]!;
      addressValueIndex += 1;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength)
        throw new Error("buffer too short for domain name");
      addressValue = new TextDecoder().decode(
        vlessBuffer.subarray(addressValueIndex, addressValueIndex + addressLength),
      );
      break;
    case 3:
      addressLength = 16;
      if (addressValueIndex + addressLength > vlessBuffer.byteLength)
        throw new Error("buffer too short for IPv6 address");
      const dataView = new DataView(vlessBuffer.buffer, vlessBuffer.byteOffset + addressValueIndex, addressLength);
      const ipv6: string[] = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      addressLength = 0;
      addressValue = "";
  }

  const data = vlessBuffer.subarray(addressValueIndex + addressLength);

  return {
    version,
    uuid,
    protoBuf,
    command: (["tcp", "udp", "mux"] as const)[command - 1],
    port,
    address: addressValue,
    data,
  };
}

/**
 * Get correct underlying ArrayBuffer for Node.js Buffers.
 * @see https://nodejs.org/api/buffer.html#bufbyteoffset
 */
function getUnderlyingArrayBuffer(b: Uint8Array) {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}
