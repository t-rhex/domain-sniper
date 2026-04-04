export interface WebhookPayload {
  domain: string;
  status: string;
  timestamp: string;
  details?: Record<string, unknown>;
}

export async function sendWebhook(
  url: string,
  payload: WebhookPayload
): Promise<{ success: boolean; error?: string }> {
  try {
    // Detect Slack vs Discord vs generic
    const isSlack = url.includes("hooks.slack.com");
    const isDiscord = url.includes("discord.com/api/webhooks");

    let body: string;

    if (isSlack) {
      body = JSON.stringify({
        text: `*Domain Sniper Alert*\n\`${payload.domain}\` is now *${payload.status.toUpperCase()}*`,
        blocks: [
          {
            type: "section",
            text: {
              type: "mrkdwn",
              text: `*Domain Sniper Alert*\n\n\`${payload.domain}\` is now *${payload.status.toUpperCase()}*\n_${payload.timestamp}_`,
            },
          },
        ],
      });
    } else if (isDiscord) {
      body = JSON.stringify({
        embeds: [{
          title: "Domain Sniper Alert",
          description: `\`${payload.domain}\` is now **${payload.status.toUpperCase()}**`,
          color: payload.status === "available" ? 0x00e88f : payload.status === "expired" ? 0xf5c542 : 0x5c9cf5,
          timestamp: payload.timestamp,
        }],
      });
    } else {
      body = JSON.stringify(payload);
    }

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      return { success: false, error: `HTTP ${resp.status}` };
    }
    return { success: true };
  } catch (err: unknown) {
    return { success: false, error: err instanceof Error ? err.message : "Webhook failed" };
  }
}

export async function sendEmailAlert(
  config: { host: string; port: number; user: string; pass: string; to: string },
  payload: WebhookPayload
): Promise<{ success: boolean; error?: string }> {
  // Use Bun's built-in TCP for basic SMTP
  try {
    const socket = await Bun.connect({
      hostname: config.host,
      port: config.port,
      socket: {
        data(_socket, _data) { /* consume responses */ },
        open(socket) {
          // Simple SMTP sequence
          setTimeout(() => {
            socket.write(`EHLO domain-sniper\r\n`);
            setTimeout(() => {
              socket.write(`AUTH LOGIN\r\n`);
              setTimeout(() => {
                socket.write(`${btoa(config.user)}\r\n`);
                setTimeout(() => {
                  socket.write(`${btoa(config.pass)}\r\n`);
                  setTimeout(() => {
                    socket.write(`MAIL FROM:<${config.user}>\r\n`);
                    setTimeout(() => {
                      socket.write(`RCPT TO:<${config.to}>\r\n`);
                      setTimeout(() => {
                        socket.write(`DATA\r\n`);
                        setTimeout(() => {
                          const msg = [
                            `From: Domain Sniper <${config.user}>`,
                            `To: ${config.to}`,
                            `Subject: Domain Alert: ${payload.domain} is ${payload.status}`,
                            `Content-Type: text/plain; charset=utf-8`,
                            ``,
                            `Domain Sniper Alert`,
                            ``,
                            `Domain: ${payload.domain}`,
                            `Status: ${payload.status.toUpperCase()}`,
                            `Time: ${payload.timestamp}`,
                            ``,
                            `---`,
                            `Sent by Domain Sniper`,
                          ].join("\r\n");
                          socket.write(`${msg}\r\n.\r\n`);
                          setTimeout(() => {
                            socket.write(`QUIT\r\n`);
                            socket.end();
                          }, 500);
                        }, 500);
                      }, 500);
                    }, 500);
                  }, 500);
                }, 500);
              }, 500);
            }, 500);
          }, 500);
        },
        close() {},
        error() {},
      },
    });
    return { success: true };
  } catch (err: unknown) {
    return { success: false, error: err instanceof Error ? err.message : "Email send failed" };
  }
}
