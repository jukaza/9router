import { CLINEPASS_CONFIG } from "../constants/oauth.js";

const DEFAULT_CLIENT_ID = "client_01K3A541FN8TA3EPPHTD2325AR";
const DEFAULT_DEVICE_CODE_URL = "https://api.workos.com/user_management/authorize/device";
const DEFAULT_AUTH_URL = "https://api.workos.com/user_management/authenticate";
const DEFAULT_REGISTER_URL = "https://api.cline.bot/api/v1/auth/register";

const clinepass = {
  config: CLINEPASS_CONFIG,
  flowType: "device_code",

  requestDeviceCode: async (config) => {
    const clientId = config?.clientId || DEFAULT_CLIENT_ID;
    const deviceUrl = config?.deviceCodeUrl || DEFAULT_DEVICE_CODE_URL;
    const response = await fetch(deviceUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        client_id: clientId,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`ClinePass device code request failed: ${error}`);
    }

    const data = await response.json();
    const userCode = data.user_code;
    return {
      device_code: data.device_code,
      user_code: userCode,
      verification_uri: data.verification_uri || "https://authkit.cline.bot/device",
      verification_uri_complete:
        data.verification_uri_complete ||
        (userCode ? `https://authkit.cline.bot/device?user_code=${encodeURIComponent(userCode)}` : "https://authkit.cline.bot/device"),
      expires_in: data.expires_in || 300,
      interval: data.interval || 5,
    };
  },

  pollToken: async (config, deviceCode) => {
    const clientId = config?.clientId || DEFAULT_CLIENT_ID;
    const tokenUrl = config?.tokenUrl || DEFAULT_AUTH_URL;
    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: clientId,
      }),
    });

    let data;
    try {
      data = await response.json();
    } catch (e) {
      const text = await response.text();
      data = { error: "invalid_response", error_description: text };
    }

    return {
      ok: response.ok,
      data,
    };
  },

  postExchange: async (tokens) => {
    const workosAccessToken = tokens.access_token;
    const workosRefreshToken = tokens.refresh_token;
    if (!workosAccessToken) return null;

    try {
      const response = await fetch(DEFAULT_REGISTER_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          accessToken: workosAccessToken,
          refreshToken: workosRefreshToken,
        }),
      });

      if (!response.ok) {
        return null;
      }

      const clineData = await response.json();
      return { clineData };
    } catch {
      return null;
    }
  },

  mapTokens: (tokens, extra) => {
    const clineInfo = extra?.clineData?.data;
    const accessToken = clineInfo?.accessToken || tokens.access_token;
    const refreshToken = clineInfo?.refreshToken || tokens.refresh_token;
    const email = clineInfo?.userInfo?.email || tokens.user?.email || "";
    const expiresIn = clineInfo?.expiresAt
      ? Math.max(1, Math.floor((new Date(clineInfo.expiresAt).getTime() - Date.now()) / 1000))
      : 3600;

    return {
      accessToken,
      refreshToken,
      expiresIn,
      email,
      name: email || "ClinePass User",
      displayName: email || "ClinePass User",
      providerSpecificData: {
        email,
        workosAccessToken: tokens.access_token,
        workosRefreshToken: tokens.refresh_token,
      },
    };
  },

  buildAuthUrl: (config, redirectUri) => {
    const params = new URLSearchParams({
      client_type: "extension",
      callback_url: redirectUri,
      redirect_uri: redirectUri,
    });
    return `${config.authorizeUrl}?${params.toString()}`;
  },

  exchangeToken: async (config, code, redirectUri) => {
    try {
      let base64 = code;
      const padding = 4 - (base64.length % 4);
      if (padding !== 4) base64 += "=".repeat(padding);
      const decoded = Buffer.from(base64, "base64").toString("utf-8");
      const lastBrace = decoded.lastIndexOf("}");
      if (lastBrace === -1) throw new Error("No JSON found in decoded code");
      const tokenData = JSON.parse(decoded.substring(0, lastBrace + 1));
      return {
        access_token: tokenData.accessToken,
        refresh_token: tokenData.refreshToken,
        email: tokenData.email,
        firstName: tokenData.firstName,
        lastName: tokenData.lastName,
        expires_at: tokenData.expiresAt,
      };
    } catch (e) {
      const response = await fetch(config.tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ grant_type: "authorization_code", code, client_type: "extension", redirect_uri: redirectUri }),
      });
      if (!response.ok) {
        const error = await response.text();
        throw new Error(`ClinePass token exchange failed: ${error}`);
      }
      const data = await response.json();
      return {
        access_token: data.data?.accessToken || data.accessToken,
        refresh_token: data.data?.refreshToken || data.refreshToken,
        email: data.data?.userInfo?.email || "",
        expires_at: data.data?.expiresAt || data.expiresAt,
      };
    }
  },
};

export default clinepass;

