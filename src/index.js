
const KEY_PREFIX = "SKUY";
const KEY_RANDOM_LENGTH = 8;
const KEY_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ============================================================
    // HEALTH CHECK
    // ============================================================

    if (request.method === "GET" && url.pathname === "/") {
      return text("SKUY AUTH SERVER ONLINE");
    }


    // ============================================================
    // LUA CLIENT AUTH
    // Jangan ubah kontrak bagian ini.
    // ============================================================

    if (request.method === "POST" && url.pathname === "/api/auth") {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const userKey = form.get("user_key") || "";
        const hwid = form.get("hwid") || "";
        const timestampRaw = form.get("timestamp") || "";
        const nonceRaw = form.get("nonce") || "";
        const clientSign = form.get("sign") || "";

        if (
          !userKey ||
          !hwid ||
          !timestampRaw ||
          !nonceRaw ||
          !clientSign
        ) {
          return text("ERROR|INVALID REQUEST");
        }

        const timestamp = Number(timestampRaw);
        const nonce = Number(nonceRaw);

        if (
          !Number.isInteger(timestamp) ||
          !Number.isInteger(nonce)
        ) {
          return text("ERROR|INVALID REQUEST");
        }

        const expectedSign = generateSign(
          userKey,
          hwid,
          timestamp,
          nonce
        );

        if (clientSign !== expectedSign) {
          return text("ERROR|INVALID SIGNATURE");
        }

        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(userKey)
          .first();

        if (!license) {
          return text("ERROR|INVALID KEY");
        }

        if (Number(license.enabled) !== 1) {
          return text("ERROR|KEY DISABLED");
        }

        const now = unixNow();

        let daysRemaining = 9999;

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return text("ERROR|INVALID EXPIRY");
          }

          if (expiresAt <= now) {
            return text("ERROR|KEY EXPIRED");
          }

          daysRemaining = Math.max(
            1,
            Math.ceil((expiresAt - now) / 86400)
          );
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, hwid)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(
              countRow?.total || 0
            );

            if (deviceCount >= maxDevices) {
              return text("ERROR|DEVICE LIMIT REACHED");
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(
                license.id,
                hwid,
                now,
                now
              )
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        return text(`OK|${daysRemaining}`);
      } catch (error) {
        console.error("AUTH ERROR:", error);
        return text("ERROR|SERVER ERROR");
      }
    }


    // ============================================================
    // MASTER / AHSAN LUA CLIENT AUTH
    // Separate protocol, shared licenses/devices D1 tables.
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/master/auth"
    ) {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const game = String(form.get("game") || "").trim();
        const userKey = String(form.get("user_key") || "").trim();
        const serial = String(form.get("serial") || "").trim();

        if (!game || !userKey || !serial) {
          return json({ status: false, reason: "Invalid request" });
        }

        if (game !== "BGMI") {
          return json({ status: false, reason: "Invalid game" });
        }

        // IMPORTANT: MASTER keys are matched exactly as supplied.
        // Do not uppercase/lowercase before lookup because the token
        // binds to the exact key string entered by the client.
        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(userKey)
          .first();

        if (!license) {
          return json({ status: false, reason: "Invalid key" });
        }

        if (Number(license.enabled) !== 1) {
          return json({ status: false, reason: "Key disabled" });
        }

        const now = unixNow();

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return json({ status: false, reason: "Invalid expiry" });
          }

          if (expiresAt <= now) {
            return json({ status: false, reason: "Expired" });
          }
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, serial)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(countRow?.total || 0);

            if (deviceCount >= maxDevices) {
              return json({ status: false, reason: "Max Devices" });
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(license.id, serial, now, now)
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        const masterSecret = String(
          env.MASTER_SECRET ||
          "Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz5E"
        );

        const token = md5Hex(
          `${game}-${userKey}-${serial}-${masterSecret}`
        );

        return json({
          status: true,
          data: {
            token,
            rng: now,
          },
        });
      } catch (error) {
        console.error("MASTER AUTH ERROR:", error);
        return json({ status: false, reason: "Server error" });
      }
    }



    // ============================================================
    // CHARACTERBASE LUA CLIENT AUTH
    // Same client protocol as MASTER, separate endpoint.
    // Shared licenses/devices D1 tables.
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/character/auth"
    ) {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const game = String(form.get("game") || "").trim();
        const userKey = String(form.get("user_key") || "").trim();
        const serial = String(form.get("serial") || "").trim();

        if (!game || !userKey || !serial) {
          return json({ status: false, reason: "Invalid request" });
        }

        if (game !== "BGMI" && game !== "PUBG") {
          return json({ status: false, reason: "Invalid game" });
        }

        // Keep the exact key spelling/case supplied by the client.
        // The token binds to this exact string.
        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(userKey)
          .first();

        if (!license) {
          return json({ status: false, reason: "Invalid key" });
        }

        if (Number(license.enabled) !== 1) {
          return json({ status: false, reason: "Key disabled" });
        }

        const now = unixNow();

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return json({ status: false, reason: "Invalid expiry" });
          }

          if (expiresAt <= now) {
            return json({ status: false, reason: "Expired" });
          }
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, serial)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(countRow?.total || 0);

            if (deviceCount >= maxDevices) {
              return json({ status: false, reason: "Max Devices" });
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(license.id, serial, now, now)
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        const characterSecret = String(
          env.CHARACTER_SECRET ||
          env.MASTER_SECRET ||
          "Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz5E"
        );

        const token = md5Hex(
          `${game}-${userKey}-${serial}-${characterSecret}`
        );

        return json({
          status: true,
          data: {
            token,
            rng: now,
          },
        });
      } catch (error) {
        console.error("CHARACTER AUTH ERROR:", error);
        return json({ status: false, reason: "Server error" });
      }
    }


    // ============================================================
    // MASTER TOOL APK CLIENT AUTH
    // Same client protocol as CHARACTERBASE, separate endpoint.
    // Shared licenses/devices D1 tables.
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/tool/auth"
    ) {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const game = String(form.get("game") || "").trim();
        const userKey = String(form.get("user_key") || "").trim();
        const serial = String(form.get("serial") || "").trim();

        if (!game || !userKey || !serial) {
          return json({ status: false, reason: "Invalid request" });
        }

        if (game !== "BGMI") {
          return json({ status: false, reason: "Invalid game" });
        }

        // Keep the exact key spelling/case supplied by the client.
        // The token binds to this exact string.
        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(userKey)
          .first();

        if (!license) {
          return json({ status: false, reason: "Invalid key" });
        }

        if (Number(license.enabled) !== 1) {
          return json({ status: false, reason: "Key disabled" });
        }

        const now = unixNow();

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return json({ status: false, reason: "Invalid expiry" });
          }

          if (expiresAt <= now) {
            return json({ status: false, reason: "Expired" });
          }
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, serial)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(countRow?.total || 0);

            if (deviceCount >= maxDevices) {
              return json({ status: false, reason: "Max Devices" });
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(license.id, serial, now, now)
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        const toolSecret = String(
          env.TOOL_SECRET ||
          env.CHARACTER_SECRET ||
          env.MASTER_SECRET ||
          "Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz5E"
        );

        const token = md5Hex(
          `${game}-${userKey}-${serial}-${toolSecret}`
        );

        return json({
          status: true,
          data: {
            token,
            rng: now,
          },
        });
      } catch (error) {
        console.error("TOOL AUTH ERROR:", error);
        return json({ status: false, reason: "Server error" });
      }
    }



    // ============================================================
    // PRODUCT-AWARE LUA AUTH - PROTOCOL P1
    // Strictly separate from legacy /api/auth.
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/product/auth"
    ) {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const protocol = String(form.get("protocol") || "").trim();
        const productCode = String(form.get("product_id") || "").trim();
        const userKey = String(form.get("user_key") || "").trim();
        const hwid = String(form.get("hwid") || "").trim();
        const timestampRaw = String(form.get("timestamp") || "").trim();
        const nonceRaw = String(form.get("nonce") || "").trim();
        const clientSign = String(form.get("sign") || "").trim();

        if (
          protocol !== "P1" ||
          !productCode ||
          !userKey ||
          !hwid ||
          !timestampRaw ||
          !nonceRaw ||
          !clientSign
        ) {
          return text("ERROR|INVALID REQUEST");
        }

        const timestamp = Number(timestampRaw);
        const nonce = Number(nonceRaw);

        if (!Number.isInteger(timestamp) || !Number.isInteger(nonce)) {
          return text("ERROR|INVALID REQUEST");
        }

        const expectedSign = generateProductSign(
          productCode,
          userKey,
          hwid,
          timestamp,
          nonce
        );

        if (clientSign !== expectedSign) {
          return text("ERROR|INVALID SIGNATURE");
        }

        const product = await env.DB
          .prepare(`
            SELECT id, product_code, product_name, product_type, enabled
            FROM products
            WHERE product_code = ?1
            LIMIT 1
          `)
          .bind(productCode)
          .first();

        // Public client error stays generic. Detailed mismatch stays server-side.
        if (!product || Number(product.enabled) !== 1 || product.product_type !== "lua") {
          console.warn("PRODUCT AUTH REJECT:", {
            productCode,
            reason: !product ? "PRODUCT_NOT_FOUND" :
                    Number(product.enabled) !== 1 ? "PRODUCT_DISABLED" :
                    "PRODUCT_TYPE_MISMATCH",
          });
          return text("ERROR|INVALID KEY");
        }

        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices,
              product_id
            FROM licenses
            WHERE license_key = ?1
              AND product_id = ?2
            LIMIT 1
          `)
          .bind(userKey, product.id)
          .first();

        if (!license) {
          const anyLicense = await env.DB
            .prepare(`
              SELECT id, product_id
              FROM licenses
              WHERE license_key = ?1
              LIMIT 1
            `)
            .bind(userKey)
            .first();

          if (anyLicense) {
            console.warn("PRODUCT AUTH REJECT:", {
              productCode,
              userKey,
              reason: anyLicense.product_id === null ?
                "LEGACY_KEY_ON_PRODUCT" : "PRODUCT_MISMATCH",
            });
          }

          return text("ERROR|INVALID KEY");
        }

        if (Number(license.enabled) !== 1) {
          return text("ERROR|KEY DISABLED");
        }

        const now = unixNow();
        let daysRemaining = 9999;

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return text("ERROR|INVALID EXPIRY");
          }

          if (expiresAt <= now) {
            return text("ERROR|KEY EXPIRED");
          }

          daysRemaining = Math.max(
            1,
            Math.ceil((expiresAt - now) / 86400)
          );
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, hwid)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(countRow?.total || 0);

            if (deviceCount >= maxDevices) {
              return text("ERROR|DEVICE LIMIT REACHED");
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(license.id, hwid, now, now)
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        return text(`OK|${daysRemaining}`);
      } catch (error) {
        console.error("PRODUCT LUA AUTH ERROR:", error);
        return text("ERROR|SERVER ERROR");
      }
    }


    // ============================================================
    // GRW PREMIUM COMPATIBILITY AUTH
    // Legacy client contract:
    // POST form: game=PUBG&user_key=<KEY>&serial=<HWID>
    // JSON response: { status, token, EXP, rng, reason? }
    //
    // Product scope is resolved server-side because the legacy GRW
    // client does not send a product id.
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/grw/auth"
    ) {
      try {
        const body = await request.text();
        const form = new URLSearchParams(body);

        const game = String(form.get("game") || "").trim();
        const userKey = String(form.get("user_key") || "").trim();
        const serial = String(form.get("serial") || "").trim();

        if (!game || !userKey || !serial) {
          return json({ status: false, reason: "Invalid request" });
        }

        if (game !== "PUBG") {
          return json({ status: false, reason: "Invalid game" });
        }

        const productCode = normalizeProductCode(
          env.GRW_PRODUCT_CODE || "GRW_PREMIUM"
        );

        const product = await env.DB
          .prepare(`
            SELECT id, product_code, product_name, product_type, enabled
            FROM products
            WHERE product_code = ?1
            LIMIT 1
          `)
          .bind(productCode)
          .first();

        if (
          !product ||
          Number(product.enabled) !== 1 ||
          product.product_type !== "lua"
        ) {
          console.warn("GRW AUTH REJECT:", {
            productCode,
            reason: !product
              ? "PRODUCT_NOT_FOUND"
              : Number(product.enabled) !== 1
              ? "PRODUCT_DISABLED"
              : "PRODUCT_TYPE_MISMATCH",
          });
          return json({ status: false, reason: "Invalid key" });
        }

        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices,
              product_id
            FROM licenses
            WHERE license_key = ?1
              AND product_id = ?2
            LIMIT 1
          `)
          .bind(userKey, product.id)
          .first();

        if (!license) {
          return json({ status: false, reason: "Invalid key" });
        }

        if (Number(license.enabled) !== 1) {
          return json({ status: false, reason: "Key disabled" });
        }

        const now = unixNow();
        let expValue = "UNLIMITED";

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          if (!Number.isFinite(expiresAt)) {
            return json({ status: false, reason: "Invalid expiry" });
          }

          if (expiresAt <= now) {
            return json({ status: false, reason: "Expired" });
          }

          expValue = String(expiresAt);
        }

        const maxDevices = Number(license.max_devices) || 0;

        if (maxDevices > 0) {
          const existingDevice = await env.DB
            .prepare(`
              SELECT id
              FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
              LIMIT 1
            `)
            .bind(license.id, serial)
            .first();

          if (existingDevice) {
            await env.DB
              .prepare(`
                UPDATE devices
                SET last_seen_at = ?1
                WHERE id = ?2
              `)
              .bind(now, existingDevice.id)
              .run();
          } else {
            const countRow = await env.DB
              .prepare(`
                SELECT COUNT(*) AS total
                FROM devices
                WHERE license_id = ?1
              `)
              .bind(license.id)
              .first();

            const deviceCount = Number(countRow?.total || 0);

            if (deviceCount >= maxDevices) {
              return json({ status: false, reason: "Max Devices" });
            }

            await env.DB
              .prepare(`
                INSERT INTO devices (
                  license_id,
                  hwid,
                  first_seen_at,
                  last_seen_at
                )
                VALUES (?1, ?2, ?3, ?4)
              `)
              .bind(license.id, serial, now, now)
              .run();
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET last_used_at = ?1
            WHERE id = ?2
          `)
          .bind(now, license.id)
          .run();

        const grwSecret = String(
          env.GRW_SECRET ||
          env.MASTER_SECRET ||
          "GRW_COMPAT"
        );

        const token = md5Hex(
          `${game}-${userKey}-${serial}-${grwSecret}`
        );

        return json({
          status: true,
          token,
          EXP: expValue,
          rng: now,
        });
      } catch (error) {
        console.error("GRW AUTH ERROR:", error);
        return json({ status: false, reason: "Server error" });
      }
    }

    // ============================================================
    // CUSTOMER API - AUTHENTICATED & CUSTOMER-SCOPED
    // ============================================================

    if (url.pathname.startsWith("/api/customer/")) {
      const access = await requireCustomerAccess(request, env);
      if (!access.ok) {
        return json(
          {
            ok: false,
            error: access.error,
            status: access.status || null,
          },
          access.httpStatus || 403
        );
      }
      const customer = access.customer;

      if (request.method === "GET" && url.pathname === "/api/customer/me") {
        return json({
          ok: true,
          customer: customerPublic(customer),
          usage: await getCustomerUsageSummary(env, customer),
        });
      }

      if (request.method === "GET" && url.pathname === "/api/customer/products") {
        const result = await env.DB.prepare(`
          SELECT p.id, p.product_code, p.product_name, p.product_type,
                 p.enabled, p.created_at, COUNT(l.id) AS license_count
          FROM products p
          LEFT JOIN licenses l ON l.product_id = p.id
          WHERE p.customer_id = ?1
          GROUP BY p.id
          ORDER BY p.created_at ASC, p.id ASC
        `).bind(customer.id).all();
        return json({ ok: true, products: result.results || [] });
      }

      if (request.method === "GET" && url.pathname === "/api/customer/product/licenses") {
        const productCode = normalizeProductCode(url.searchParams.get("product_id"));
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const result = await env.DB.prepare(`
          SELECT l.id, l.license_key, l.enabled, l.expires_at,
                 l.max_devices, l.created_at, l.last_used_at,
                 COUNT(d.id) AS device_count
          FROM licenses l
          LEFT JOIN devices d ON d.license_id = l.id
          WHERE l.product_id = ?1
          GROUP BY l.id
          ORDER BY l.created_at DESC
        `).bind(product.id).all();
        return json({ ok: true, product: productPublic(product), licenses: result.results || [] });
      }

      if (request.method === "GET" && url.pathname === "/api/customer/product/license") {
        const productCode = normalizeProductCode(url.searchParams.get("product_id"));
        const licenseKey = normalizeAdminKey(url.searchParams.get("key"));
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        if (!licenseKey) return json({ ok: false, error: "KEY REQUIRED" }, 400);

        const license = await env.DB.prepare(`
          SELECT id, license_key, enabled, expires_at, max_devices, created_at, last_used_at
          FROM licenses
          WHERE license_key = ?1 AND product_id = ?2
          LIMIT 1
        `).bind(licenseKey, product.id).first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        const devices = await env.DB.prepare(`
          SELECT hwid, first_seen_at, last_seen_at
          FROM devices WHERE license_id = ?1 ORDER BY first_seen_at ASC
        `).bind(license.id).all();

        const now = unixNow();
        let daysRemaining = null;
        let expired = false;
        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);
          expired = expiresAt <= now;
          daysRemaining = expired ? 0 : Math.ceil((expiresAt - now) / 86400);
        }
        return json({
          ok: true,
          product: productPublic(product),
          license: {
            license_key: license.license_key,
            enabled: Number(license.enabled),
            expires_at: license.expires_at,
            days_remaining: daysRemaining,
            expired,
            max_devices: Number(license.max_devices) || 0,
            created_at: license.created_at,
            last_used_at: license.last_used_at,
            devices: devices.results || [],
          },
        });
      }

      if (request.method === "POST" && url.pathname === "/api/customer/product/create-license") {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        if (Number(product.enabled) !== 1) return json({ ok: false, error: "PRODUCT DISABLED" }, 403);

        const count = Number(body.count || 1);
        const maxDevices = Number(body.max_devices ?? 1);
        const expiryDays = body.expires_in_days === null || body.expires_in_days === undefined
          ? null : Number(body.expires_in_days);
        if (!Number.isInteger(count) || count < 1 || count > 100) {
          return json({ ok: false, error: "COUNT MUST BE 1-100" }, 400);
        }
        if (!Number.isInteger(maxDevices) || maxDevices < 0) {
          return json({ ok: false, error: "INVALID MAX DEVICES" }, 400);
        }
        if (expiryDays !== null && (!Number.isInteger(expiryDays) || expiryDays < 1)) {
          return json({ ok: false, error: "INVALID EXPIRY DAYS" }, 400);
        }

        const quotaError = await checkCustomerCreateQuota(
          env, customer, product.id, count, maxDevices, expiryDays
        );
        if (quotaError) return json({ ok: false, error: quotaError }, 403);

        const keys = await generateUniqueKeys(env, count);
        const now = unixNow();
        const expiresAt = expiryDays === null ? null : now + expiryDays * 86400;
        const statements = keys.map(key => env.DB.prepare(`
          INSERT INTO licenses (
            license_key, enabled, expires_at, max_devices, created_at, last_used_at, product_id
          ) VALUES (?1, 1, ?2, ?3, ?4, NULL, ?5)
        `).bind(key, expiresAt, maxDevices, now, product.id));
        if (statements.length) await env.DB.batch(statements);
        await incrementCustomerDailyUsage(env, customer.id, "keys_created", count);
        await writeAudit(env,{
          actorType:"CUSTOMER",actorId:customer.customer_code,
          category:"LICENSE",action:"LICENSES_CREATED",
          targetType:"PRODUCT",targetId:product.product_code,
          message:`Customer ${customer.customer_name} membuat ${count} key untuk product ${product.product_name}.`
        });

        return json({
          ok: true,
          product: productPublic(product),
          licenses: keys.map(k => ({
            license_key: k,
            expires_at: expiresAt,
            expires_in_days: expiryDays,
            max_devices: maxDevices,
          })),
        });
      }

      if (request.method === "POST" && url.pathname === "/api/customer/product/update-license") {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        if (!licenseKey) return json({ ok: false, error: "KEY REQUIRED" }, 400);

        const license = await env.DB.prepare(`
          SELECT id, enabled, expires_at, max_devices
          FROM licenses WHERE license_key=?1 AND product_id=?2 LIMIT 1
        `).bind(licenseKey, product.id).first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        let enabled = Number(license.enabled);
        let expiresAt = license.expires_at;
        let maxDevices = Number(license.max_devices) || 0;
        const now = unixNow();

        if (body.enabled !== undefined) {
          const v = Number(body.enabled);
          if (v !== 0 && v !== 1) return json({ ok: false, error: "INVALID ENABLED" }, 400);
          if (v === 1 && enabled !== 1 && isLimited(customer.max_active_keys)) {
            const active = await countCustomerActiveKeys(env, customer.id);
            if (active >= Number(customer.max_active_keys)) {
              return json({ ok: false, error: "CUSTOMER ACTIVE KEY LIMIT" }, 403);
            }
          }
          enabled = v;
        }

        if (body.max_devices !== undefined) {
          const v = Number(body.max_devices);
          if (!Number.isInteger(v) || v < 0) return json({ ok: false, error: "INVALID MAX DEVICES" }, 400);
          if (isLimited(customer.max_devices_per_key) &&
              (v === 0 || v > Number(customer.max_devices_per_key))) {
            return json({ ok: false, error: "CUSTOMER DEVICE LIMIT" }, 403);
          }
          maxDevices = v;
        }

        if (body.expiry_action !== undefined) {
          const action = String(body.expiry_action || "");
          if (action === "unlimited") {
            if (isLimited(customer.max_license_days)) {
              return json({ ok: false, error: "UNLIMITED EXPIRY NOT ALLOWED" }, 403);
            }
            expiresAt = null;
          } else {
            const days = Number(body.expiry_days);
            if (!Number.isInteger(days) || days < 1) {
              return json({ ok: false, error: "INVALID EXPIRY DAYS" }, 400);
            }
            if (isLimited(customer.max_license_days) && days > Number(customer.max_license_days)) {
              return json({ ok: false, error: "CUSTOMER LICENSE DAY LIMIT" }, 403);
            }
            if (action === "set_from_now") {
              expiresAt = now + days * 86400;
            } else if (action === "add_days") {
              const base = expiresAt === null ? now : Math.max(now, Number(expiresAt));
              const proposed = base + days * 86400;
              if (isLimited(customer.max_license_days) &&
                  proposed > now + Number(customer.max_license_days) * 86400) {
                return json({ ok: false, error: "CUSTOMER LICENSE DAY LIMIT" }, 403);
              }
              expiresAt = proposed;
            } else {
              return json({ ok: false, error: "INVALID EXPIRY ACTION" }, 400);
            }
          }
        }

        await env.DB.prepare(`
          UPDATE licenses SET enabled=?1, expires_at=?2, max_devices=?3 WHERE id=?4
        `).bind(enabled, expiresAt, maxDevices, license.id).run();
        await writeAudit(env,{
          actorType:"CUSTOMER",actorId:customer.customer_code,
          category:"LICENSE",action:"LICENSE_UPDATED",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Customer ${customer.customer_name} memperbarui key ${shortAuditId(licenseKey)} pada product ${product.product_name}.`
        });
        return json({ ok: true, message: "LICENSE UPDATED" });
      }

      if (request.method === "POST" && url.pathname === "/api/customer/product/reset-device") {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const license = await env.DB.prepare(`
          SELECT id FROM licenses WHERE license_key=?1 AND product_id=?2 LIMIT 1
        `).bind(licenseKey, product.id).first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        const daily = await getCustomerDailyUsage(env, customer.id);
        if (isLimited(customer.reset_limit_per_day) &&
            Number(daily.hwid_resets || 0) >= Number(customer.reset_limit_per_day)) {
          return json({ ok: false, error: "CUSTOMER DAILY RESET LIMIT" }, 403);
        }

        let result;
        if (body.all === true) {
          result = await env.DB.prepare(`DELETE FROM devices WHERE license_id=?1`)
            .bind(license.id).run();
        } else {
          const hwid = String(body.hwid || "").trim();
          if (!hwid) return json({ ok: false, error: "HWID REQUIRED" }, 400);
          result = await env.DB.prepare(`
            DELETE FROM devices WHERE license_id=?1 AND hwid=?2
          `).bind(license.id, hwid).run();
        }
        await incrementCustomerDailyUsage(env, customer.id, "hwid_resets", 1);
        await writeAudit(env,{
          actorType:"CUSTOMER",actorId:customer.customer_code,
          category:"LICENSE",action:"LICENSE_DEVICE_RESET",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Customer ${customer.customer_name} mereset binding device key ${shortAuditId(licenseKey)} pada product ${product.product_name}.`
        });
        return json({ ok: true, removed: Number(result?.meta?.changes || 0) });
      }

      if (request.method === "POST" && url.pathname === "/api/customer/product/delete-license") {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        const product = productCode ? await getCustomerProductByCode(env, customer.id, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        const license = await env.DB.prepare(`
          SELECT id FROM licenses WHERE license_key=?1 AND product_id=?2 LIMIT 1
        `).bind(licenseKey, product.id).first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM devices WHERE license_id=?1`).bind(license.id),
          env.DB.prepare(`DELETE FROM licenses WHERE id=?1`).bind(license.id),
        ]);
        await writeAudit(env,{
          actorType:"CUSTOMER",actorId:customer.customer_code,
          category:"LICENSE",action:"LICENSE_DELETED",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Customer ${customer.customer_name} menghapus key ${shortAuditId(licenseKey)} dari product ${product.product_name}.`
        });
        return json({ ok: true, message: "LICENSE DELETED" });
      }

      return json({ ok: false, error: "CUSTOMER API NOT FOUND" }, 404);
    }

    // ============================================================
    // ADMIN API AUTH
    // ============================================================

    if (url.pathname.startsWith("/api/admin/")) {
      if (!isAdmin(request, env)) {
        return json(
          {
            ok: false,
            error: "UNAUTHORIZED",
          },
          401
        );
      }
    }



    // ============================================================
    // ADMIN - AUDIT LOG
    // ============================================================
    if (request.method === "GET" && url.pathname === "/api/admin/audit") {
      try {
        const allowed=["CUSTOMER","PRODUCT","LICENSE","SECURITY"];
        const raw=String(url.searchParams.get("category") || "").trim().toUpperCase();
        const category=allowed.includes(raw) ? raw : "";
        const q=String(url.searchParams.get("q") || "").trim().slice(0,120);
        const page=Math.max(1,parseInt(url.searchParams.get("page") || "1",10) || 1);
        const limit=Math.min(50,Math.max(5,parseInt(url.searchParams.get("limit") || "10",10) || 10));
        const offset=(page-1)*limit;

        const where=[];
        const args=[];
        if (category) {
          args.push(category);
          where.push(`category=?${args.length}`);
        }
        if (q) {
          args.push(`%${q}%`);
          const i=args.length;
          where.push(`(message LIKE ?${i} OR COALESCE(target_id,'') LIKE ?${i} OR COALESCE(actor_id,'') LIKE ?${i})`);
        }
        const ws=where.length ? `WHERE ${where.join(" AND ")}` : "";

        const count=await env.DB.prepare(`SELECT COUNT(*) AS total FROM audit_logs ${ws}`)
          .bind(...args).first();

        const rows=await env.DB.prepare(`
          SELECT id,actor_type,actor_id,category,action,target_type,target_id,message,created_at
          FROM audit_logs
          ${ws}
          ORDER BY created_at DESC,id DESC
          LIMIT ?${args.length+1} OFFSET ?${args.length+2}
        `).bind(...args,limit,offset).all();

        const total=Number(count?.total || 0);
        return json({
          ok:true,
          page,
          limit,
          total,
          total_pages:Math.max(1,Math.ceil(total/limit)),
          logs:rows.results || [],
        });
      } catch (error) {
        console.error("ADMIN AUDIT LIST ERROR:",error);
        return json({ok:false,error:"AUDIT LOG FAILED"},500);
      }
    }

    // ============================================================
    // ADMIN - CUSTOMERS
    // ============================================================

    if (request.method === "GET" && url.pathname === "/api/admin/customers") {
      try {
        const result = await env.DB.prepare(`
          SELECT c.*, COUNT(DISTINCT p.id) AS product_count,
                 COUNT(DISTINCT l.id) AS total_keys
          FROM customers c
          LEFT JOIN products p ON p.customer_id = c.id
          LEFT JOIN licenses l ON l.product_id = p.id
          GROUP BY c.id
          ORDER BY c.created_at ASC, c.id ASC
        `).all();

        const customers = [];
        for (const c of (result.results || [])) {
          customers.push({
            ...customerPublic(c),
            product_count: Number(c.product_count || 0),
            total_keys: Number(c.total_keys || 0),
            active_keys: await countCustomerActiveKeys(env, c.id),
          });
        }
        return json({ ok: true, customers });
      } catch (error) {
        console.error("ADMIN CUSTOMER LIST ERROR:", error);
        return json({ ok: false, error: "DATABASE ERROR" }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/admin/customer") {
      try {
        const code = normalizeCustomerCode(url.searchParams.get("customer_id"));
        if (!code) return json({ ok: false, error: "CUSTOMER ID REQUIRED" }, 400);
        const customer = await getCustomerByCode(env, code);
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const products = await env.DB.prepare(`
          SELECT p.id, p.product_code, p.product_name, p.product_type,
                 p.enabled, p.created_at,
                 COUNT(l.id) AS license_count
          FROM products p
          LEFT JOIN licenses l ON l.product_id = p.id
          WHERE p.customer_id = ?1
          GROUP BY p.id
          ORDER BY p.created_at ASC, p.id ASC
        `).bind(customer.id).all();

        return json({
          ok: true,
          customer: customerPublic(customer),
          usage: await getCustomerUsageSummary(env, customer),
          products: products.results || [],
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER DETAIL ERROR:", error);
        return json({ ok: false, error: "DATABASE ERROR" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/create") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const customerName = String(body.customer_name || "").trim();
        if (!customerName) return json({ ok: false, error: "CUSTOMER NAME REQUIRED" }, 400);
        const limits = normalizeCustomerLimits(body);
        if (!limits.ok) return json({ ok: false, error: limits.error }, 400);

        const subscriptionDays = Number(body.subscription_days);
        if (!Number.isInteger(subscriptionDays) || subscriptionDays < 1) {
          return json({ ok: false, error: "SUBSCRIPTION DAYS REQUIRED" }, 400);
        }

        const customerCode = await generateUniqueCustomerCode(env);
        const credential = generateCustomerCredential();
        const credentialHash = await sha256Hex(credential);
        const now = unixNow();
        const subscriptionExpiresAt = now + subscriptionDays * 86400;

        await env.DB.prepare(`
          INSERT INTO customers (
            customer_code, customer_name, credential_hash, enabled,
            max_products, max_total_keys, max_keys_per_product, max_active_keys,
            max_devices_per_key, max_license_days, create_limit_per_day,
            reset_limit_per_day, created_at, updated_at, subscription_expires_at
          ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        `).bind(
          customerCode, customerName, credentialHash,
          limits.max_products, limits.max_total_keys,
          limits.max_keys_per_product, limits.max_active_keys,
          limits.max_devices_per_key, limits.max_license_days,
          limits.create_limit_per_day, limits.reset_limit_per_day,
          now, now, subscriptionExpiresAt
        ).run();

        const customer = await getCustomerByCode(env, customerCode);
        await writeAudit(env,{
          actorType:"OWNER",category:"CUSTOMER",action:"CUSTOMER_CREATED",
          targetType:"CUSTOMER",targetId:customerCode,
          message:`Customer ${customerName} dibuat oleh Owner dengan subscription ${subscriptionDays} hari.`
        });
        return json({
          ok: true,
          message: "CUSTOMER CREATED",
          customer: customerPublic(customer),
          credential,
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER CREATE ERROR:", error);
        return json({ ok: false, error: "CREATE CUSTOMER FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/update") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const code = normalizeCustomerCode(body.customer_id);
        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        let name = customer.customer_name;
        let enabled = Number(customer.enabled);
        if (body.customer_name !== undefined) {
          name = String(body.customer_name || "").trim();
          if (!name) return json({ ok: false, error: "INVALID CUSTOMER NAME" }, 400);
        }
        if (body.enabled !== undefined) {
          const v = Number(body.enabled);
          if (v !== 0 && v !== 1) return json({ ok: false, error: "ENABLED MUST BE 0 OR 1" }, 400);
          enabled = v;
        }

        const merged = {
          max_products: body.max_products ?? customer.max_products,
          max_total_keys: body.max_total_keys ?? customer.max_total_keys,
          max_keys_per_product: body.max_keys_per_product ?? customer.max_keys_per_product,
          max_active_keys: body.max_active_keys ?? customer.max_active_keys,
          max_devices_per_key: body.max_devices_per_key ?? customer.max_devices_per_key,
          max_license_days: body.max_license_days ?? customer.max_license_days,
          create_limit_per_day: body.create_limit_per_day ?? customer.create_limit_per_day,
          reset_limit_per_day: body.reset_limit_per_day ?? customer.reset_limit_per_day,
        };
        const limits = normalizeCustomerLimits(merged);
        if (!limits.ok) return json({ ok: false, error: limits.error }, 400);

        await env.DB.prepare(`
          UPDATE customers SET
            customer_name=?1, enabled=?2,
            max_products=?3, max_total_keys=?4, max_keys_per_product=?5,
            max_active_keys=?6, max_devices_per_key=?7, max_license_days=?8,
            create_limit_per_day=?9, reset_limit_per_day=?10, updated_at=?11
          WHERE id=?12
        `).bind(
          name, enabled,
          limits.max_products, limits.max_total_keys, limits.max_keys_per_product,
          limits.max_active_keys, limits.max_devices_per_key, limits.max_license_days,
          limits.create_limit_per_day, limits.reset_limit_per_day,
          unixNow(), customer.id
        ).run();

        const auditUpdated=await getCustomerByCode(env,code);
        if (body.enabled !== undefined && Number(customer.enabled)!==Number(auditUpdated.enabled)) {
          await writeAudit(env,{
            actorType:"OWNER",category:"CUSTOMER",
            action:Number(auditUpdated.enabled)===1 ? "CUSTOMER_ENABLED":"CUSTOMER_DISABLED",
            targetType:"CUSTOMER",targetId:code,
            message:`Customer ${auditUpdated.customer_name} ${Number(auditUpdated.enabled)===1 ? "diaktifkan":"dinonaktifkan"} oleh Owner.`
          });
        } else {
          await writeAudit(env,{
            actorType:"OWNER",category:"CUSTOMER",action:"CUSTOMER_LIMITS_UPDATED",
            targetType:"CUSTOMER",targetId:code,
            message:`Batas penggunaan customer ${auditUpdated.customer_name} diperbarui oleh Owner.`
          });
        }
        return json({
          ok: true,
          message: "CUSTOMER UPDATED",
          customer: customerPublic(auditUpdated),
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER UPDATE ERROR:", error);
        return json({ ok: false, error: "UPDATE CUSTOMER FAILED" }, 500);
      }
    }


    // ============================================================
    // CUSTOMER SUBSCRIPTION - OWNER ONLY
    // ============================================================
    if (request.method === "POST" && url.pathname === "/api/admin/customers/subscription") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const code = normalizeCustomerCode(body.customer_id);
        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const action = String(body.action || "");
        const days = Number(body.days);
        if (!Number.isInteger(days) || days < 1) {
          return json({ ok: false, error: "INVALID SUBSCRIPTION DAYS" }, 400);
        }

        const now = unixNow();
        let expiresAt;

        if (action === "set_from_now") {
          expiresAt = now + days * 86400;
        } else if (action === "add_days") {
          const current = Number(customer.subscription_expires_at || 0);
          const base = current > now ? current : now;
          expiresAt = base + days * 86400;
        } else {
          return json({ ok: false, error: "INVALID SUBSCRIPTION ACTION" }, 400);
        }

        await env.DB.prepare(`
          UPDATE customers
          SET subscription_expires_at=?1, updated_at=?2
          WHERE id=?3
        `).bind(expiresAt, now, customer.id).run();

        await writeAudit(env,{
          actorType:"OWNER",category:"CUSTOMER",
          action:action==="add_days" ? "SUBSCRIPTION_EXTENDED":"SUBSCRIPTION_SET",
          targetType:"CUSTOMER",targetId:code,
          message:action==="add_days"
            ? `Masa aktif customer ${customer.customer_name} ditambah ${days} hari.`
            : `Masa aktif customer ${customer.customer_name} diset ${days} hari dari sekarang.`
        });
        return json({
          ok: true,
          message: "SUBSCRIPTION UPDATED",
          customer: customerPublic(await getCustomerByCode(env, code)),
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER SUBSCRIPTION ERROR:", error);
        return json({ ok: false, error: "SUBSCRIPTION UPDATE FAILED" }, 500);
      }
    }

    // ============================================================
    // CUSTOMER ADMIN DEVICES - OWNER ONLY
    // ============================================================
    if (request.method === "GET" && url.pathname === "/api/admin/customer/devices") {
      try {
        const code = normalizeCustomerCode(url.searchParams.get("customer_id"));
        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const result = await env.DB.prepare(`
          SELECT id, device_hash, device_label, enabled, first_seen_at, last_seen_at
          FROM customer_admin_devices
          WHERE customer_id=?1
          ORDER BY first_seen_at ASC, id ASC
        `).bind(customer.id).all();

        return json({
          ok: true,
          customer: customerPublic(customer),
          devices: result.results || [],
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER DEVICE LIST ERROR:", error);
        return json({ ok: false, error: "DEVICE LIST FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customer/device-update") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const code = normalizeCustomerCode(body.customer_id);
        const deviceHash = String(body.device_hash || "").trim().toLowerCase();
        const enabled = Number(body.enabled);

        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);
        if (!/^[0-9a-f]{64}$/.test(deviceHash)) {
          return json({ ok: false, error: "INVALID DEVICE ID" }, 400);
        }
        if (enabled !== 0 && enabled !== 1) {
          return json({ ok: false, error: "INVALID DEVICE STATUS" }, 400);
        }

        const result = await env.DB.prepare(`
          UPDATE customer_admin_devices
          SET enabled=?1, last_seen_at=?2
          WHERE customer_id=?3 AND device_hash=?4
        `).bind(enabled, unixNow(), customer.id, deviceHash).run();

        const changed = Number(result?.meta?.changes || 0);
        if (!changed) return json({ ok: false, error: "DEVICE NOT FOUND" }, 404);

        await writeAudit(env,{
          actorType:"OWNER",category:"SECURITY",
          action:enabled ? "CUSTOMER_DEVICE_APPROVED":"CUSTOMER_DEVICE_BLOCKED",
          targetType:"CUSTOMER_DEVICE",targetId:deviceHash,
          message:`Device customer ${customer.customer_name} ${enabled ? "disetujui":"diblokir"} oleh Owner. Device: ${shortAuditId(deviceHash)}.`
        });
        return json({
          ok: true,
          message: enabled ? "DEVICE APPROVED" : "DEVICE BLOCKED",
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER DEVICE UPDATE ERROR:", error);
        return json({ ok: false, error: "DEVICE UPDATE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customer/devices-reset") {
      try {
        const body = await readJson(request);
        const code = normalizeCustomerCode(body?.customer_id);
        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        await env.DB.prepare(`
          DELETE FROM customer_admin_devices
          WHERE customer_id=?1
        `).bind(customer.id).run();

        await writeAudit(env,{
          actorType:"OWNER",category:"SECURITY",action:"CUSTOMER_DEVICE_BINDINGS_RESET",
          targetType:"CUSTOMER",targetId:code,
          message:`Semua binding device Customer Admin milik ${customer.customer_name} direset oleh Owner.`
        });
        return json({
          ok: true,
          message: "CUSTOMER ADMIN DEVICE BINDING RESET",
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER DEVICE RESET ERROR:", error);
        return json({ ok: false, error: "DEVICE RESET FAILED" }, 500);
      }
    }


    // ============================================================
    // CUSTOMER RENAME / DELETE / REUSE - OWNER ONLY
    // ============================================================
    if (request.method === "POST" && url.pathname === "/api/admin/customers/rename") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const code = normalizeCustomerCode(body.customer_id);
        const newName = String(body.customer_name || "").trim();
        if (!code) return json({ ok: false, error: "CUSTOMER ID REQUIRED" }, 400);
        if (!newName) return json({ ok: false, error: "CUSTOMER NAME REQUIRED" }, 400);
        if (newName.length > 120) return json({ ok: false, error: "CUSTOMER NAME TOO LONG" }, 400);

        const customer = await getCustomerByCode(env, code);
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const auditOldName=customer.customer_name;
        await env.DB.prepare(`
          UPDATE customers
          SET customer_name=?1, updated_at=?2
          WHERE id=?3
        `).bind(newName, unixNow(), customer.id).run();
        await writeAudit(env,{
          actorType:"OWNER",category:"CUSTOMER",action:"CUSTOMER_RENAMED",
          targetType:"CUSTOMER",targetId:code,
          message:`Brand customer ${auditOldName} diganti menjadi ${newName}.`
        });

        return json({
          ok: true,
          message: "CUSTOMER RENAMED",
          customer: customerPublic(await getCustomerByCode(env, code)),
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER RENAME ERROR:", error);
        return json({ ok: false, error: "CUSTOMER RENAME FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/delete") {
      try {
        const body = await readJson(request);
        const code = normalizeCustomerCode(body?.customer_id);
        if (!code) return json({ ok: false, error: "CUSTOMER ID REQUIRED" }, 400);

        const customer = await getCustomerByCode(env, code);
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const productCountRow = await env.DB.prepare(`
          SELECT COUNT(*) AS total
          FROM products
          WHERE customer_id=?1
        `).bind(customer.id).first();

        const productCount = Number(productCountRow?.total || 0);
        if (productCount > 0) {
          return json({
            ok: false,
            error: "CUSTOMER HAS PRODUCTS",
            product_count: productCount,
          }, 409);
        }

        await writeAudit(env,{
          actorType:"OWNER",category:"CUSTOMER",action:"CUSTOMER_DELETED",
          targetType:"CUSTOMER",targetId:code,
          message:`Customer ${customer.customer_name} dihapus oleh Owner.`
        });

        await env.DB.batch([
          env.DB.prepare(`
            DELETE FROM customer_admin_devices
            WHERE customer_id=?1
          `).bind(customer.id),
          env.DB.prepare(`
            DELETE FROM customer_daily_usage
            WHERE customer_id=?1
          `).bind(customer.id),
          env.DB.prepare(`
            DELETE FROM customers
            WHERE id=?1
          `).bind(customer.id),
        ]);

        return json({
          ok: true,
          message: "CUSTOMER DELETED",
          customer_id: code,
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER DELETE ERROR:", error);
        return json({ ok: false, error: "CUSTOMER DELETE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/reuse") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const code = normalizeCustomerCode(body.customer_id);
        const newName = String(body.customer_name || "").trim();
        const subscriptionDays = Number(body.subscription_days);

        if (!code) return json({ ok: false, error: "CUSTOMER ID REQUIRED" }, 400);
        if (!newName) return json({ ok: false, error: "CUSTOMER NAME REQUIRED" }, 400);
        if (newName.length > 120) return json({ ok: false, error: "CUSTOMER NAME TOO LONG" }, 400);
        if (!Number.isInteger(subscriptionDays) || subscriptionDays < 1) {
          return json({ ok: false, error: "INVALID SUBSCRIPTION DAYS" }, 400);
        }

        const customer = await getCustomerByCode(env, code);
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);

        const credential = generateCustomerCredential();
        const credentialHash = await sha256Hex(credential);
        const now = unixNow();
        const subscriptionExpiresAt = now + subscriptionDays * 86400;

        await env.DB.batch([
          env.DB.prepare(`
            UPDATE customers
            SET customer_name=?1,
                credential_hash=?2,
                enabled=1,
                subscription_expires_at=?3,
                updated_at=?4
            WHERE id=?5
          `).bind(
            newName,
            credentialHash,
            subscriptionExpiresAt,
            now,
            customer.id
          ),
          env.DB.prepare(`
            DELETE FROM customer_admin_devices
            WHERE customer_id=?1
          `).bind(customer.id),
          env.DB.prepare(`
            DELETE FROM customer_daily_usage
            WHERE customer_id=?1
          `).bind(customer.id),
        ]);

        await writeAudit(env,{
          actorType:"OWNER",category:"CUSTOMER",action:"CUSTOMER_REUSED",
          targetType:"CUSTOMER",targetId:code,
          message:`Customer dipakai ulang sebagai ${newName}. Credential dan binding device lama direset, subscription baru ${subscriptionDays} hari.`
        });
        return json({
          ok: true,
          message: "CUSTOMER REUSED",
          customer: customerPublic(await getCustomerByCode(env, code)),
          credential,
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER REUSE ERROR:", error);
        return json({ ok: false, error: "CUSTOMER REUSE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/regenerate-credential") {
      try {
        const body = await readJson(request);
        const code = normalizeCustomerCode(body?.customer_id);
        const customer = code ? await getCustomerByCode(env, code) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);
        const credential = generateCustomerCredential();
        const credentialHash = await sha256Hex(credential);
        await env.DB.prepare(`
          UPDATE customers SET credential_hash=?1, updated_at=?2 WHERE id=?3
        `).bind(credentialHash, unixNow(), customer.id).run();
        await writeAudit(env,{
          actorType:"OWNER",category:"SECURITY",action:"CUSTOMER_CREDENTIAL_REGENERATED",
          targetType:"CUSTOMER",targetId:code,
          message:`Credential customer ${customer.customer_name} dibuat ulang. Credential lama otomatis tidak berlaku.`
        });
        return json({
          ok: true,
          message: "CREDENTIAL REGENERATED",
          customer: customerPublic(customer),
          credential,
        });
      } catch (error) {
        console.error("ADMIN CUSTOMER CREDENTIAL ERROR:", error);
        return json({ ok: false, error: "REGENERATE CREDENTIAL FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/assign-product") {
      try {
        const body = await readJson(request);
        const code = normalizeCustomerCode(body?.customer_id);
        const productCode = normalizeProductCode(body?.product_id);
        const customer = code ? await getCustomerByCode(env, code) : null;
        const product = productCode ? await getProductByCode(env, productCode) : null;
        if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const count = await countCustomerProducts(env, customer.id);
        if (Number(product.customer_id) !== Number(customer.id) &&
            isLimited(customer.max_products) && count >= Number(customer.max_products)) {
          return json({ ok: false, error: "CUSTOMER PRODUCT LIMIT" }, 403);
        }
        await env.DB.prepare(`UPDATE products SET customer_id=?1 WHERE id=?2`)
          .bind(customer.id, product.id).run();
        await writeAudit(env,{
          actorType:"OWNER",category:"PRODUCT",action:"PRODUCT_ASSIGNED",
          targetType:"PRODUCT",targetId:product.product_code,
          message:`Product ${product.product_name} diberikan/dipindahkan ke customer ${customer.customer_name}.`
        });
        return json({ ok: true, message: "PRODUCT ASSIGNED" });
      } catch (error) {
        console.error("ADMIN ASSIGN PRODUCT ERROR:", error);
        return json({ ok: false, error: "ASSIGN PRODUCT FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/customers/unassign-product") {
      try {
        const body = await readJson(request);
        const productCode = normalizeProductCode(body?.product_id);
        const product = productCode ? await getProductByCode(env, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        await env.DB.prepare(`UPDATE products SET customer_id=NULL WHERE id=?1`)
          .bind(product.id).run();
        await writeAudit(env,{
          actorType:"OWNER",category:"PRODUCT",action:"PRODUCT_UNASSIGNED",
          targetType:"PRODUCT",targetId:product.product_code,
          message:`Product ${product.product_name} dilepas dari customer dan menjadi unassigned.`
        });
        return json({ ok: true, message: "PRODUCT UNASSIGNED" });
      } catch (error) {
        console.error("ADMIN UNASSIGN PRODUCT ERROR:", error);
        return json({ ok: false, error: "UNASSIGN PRODUCT FAILED" }, 500);
      }
    }

    // ============================================================
    // ADMIN - PRODUCTS
    // ============================================================

    if (request.method === "GET" && url.pathname === "/api/admin/products") {
      try {
        const result = await env.DB
          .prepare(`
            SELECT
              p.id,
              p.product_code,
              p.product_name,
              p.product_type,
              p.enabled,
              p.created_at,
              p.customer_id,
              c.customer_code,
              c.customer_name,
              COUNT(l.id) AS license_count
            FROM products p
            LEFT JOIN customers c ON c.id = p.customer_id
            LEFT JOIN licenses l
              ON l.product_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at ASC, p.id ASC
          `)
          .all();

        return json({ ok: true, products: result.results || [] });
      } catch (error) {
        console.error("ADMIN PRODUCT LIST ERROR:", error);
        return json({ ok: false, error: "DATABASE ERROR" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/products/create") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const productCode = normalizeProductCode(body.product_id);
        const productName = String(body.product_name || "").trim();
        const productType = String(body.product_type || "").trim().toLowerCase();

        if (!productCode || !productName || !["lua", "apk"].includes(productType)) {
          return json({ ok: false, error: "INVALID PRODUCT DATA" }, 400);
        }

        const existing = await env.DB
          .prepare(`SELECT id FROM products WHERE product_code = ?1 LIMIT 1`)
          .bind(productCode)
          .first();

        if (existing) return json({ ok: false, error: "PRODUCT ID ALREADY EXISTS" }, 409);

        let customer = null;
        const customerCode = normalizeCustomerCode(body.customer_id);
        if (customerCode) {
          customer = await getCustomerByCode(env, customerCode);
          if (!customer) return json({ ok: false, error: "CUSTOMER NOT FOUND" }, 404);
          if (Number(customer.enabled) !== 1) return json({ ok: false, error: "CUSTOMER DISABLED" }, 403);
          const productCount = await countCustomerProducts(env, customer.id);
          if (isLimited(customer.max_products) && productCount >= Number(customer.max_products)) {
            return json({ ok: false, error: "CUSTOMER PRODUCT LIMIT" }, 403);
          }
        }

        const createdAt = unixNow();
        await env.DB
          .prepare(`
            INSERT INTO products (
              product_code, product_name, product_type, enabled, created_at, customer_id
            ) VALUES (?1, ?2, ?3, 1, ?4, ?5)
          `)
          .bind(productCode, productName, productType, createdAt, customer ? customer.id : null)
          .run();

        await writeAudit(env,{
          actorType:"OWNER",category:"PRODUCT",action:"PRODUCT_CREATED",
          targetType:"PRODUCT",targetId:productCode,
          message:`Product ${productName} (${productCode}) dibuat oleh Owner${customer ? ` untuk customer ${customer.customer_name}` : ""}.`
        });
        return json({
          ok: true,
          message: "PRODUCT CREATED",
          product: {
            product_id: productCode,
            product_name: productName,
            product_type: productType,
            enabled: 1,
            created_at: createdAt,
            customer_id: customer ? customer.customer_code : null,
            customer_name: customer ? customer.customer_name : null,
          },
        });
      } catch (error) {
        console.error("ADMIN PRODUCT CREATE ERROR:", error);
        return json({ ok: false, error: "CREATE PRODUCT FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/products/update") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const productCode = normalizeProductCode(body.product_id);
        if (!productCode) return json({ ok: false, error: "PRODUCT ID REQUIRED" }, 400);

        const product = await env.DB
          .prepare(`
            SELECT id, product_code, product_name, product_type, enabled
            FROM products
            WHERE product_code = ?1
            LIMIT 1
          `)
          .bind(productCode)
          .first();

        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        let productName = product.product_name;
        let enabled = Number(product.enabled);

        if (body.product_name !== undefined) {
          const value = String(body.product_name || "").trim();
          if (!value) return json({ ok: false, error: "INVALID PRODUCT NAME" }, 400);
          productName = value;
        }

        if (body.enabled !== undefined) {
          const value = Number(body.enabled);
          if (value !== 0 && value !== 1) return json({ ok: false, error: "ENABLED MUST BE 0 OR 1" }, 400);
          enabled = value;
        }

        // product_code and product_type are intentionally immutable in V1.
        await env.DB
          .prepare(`
            UPDATE products
            SET product_name = ?1, enabled = ?2
            WHERE id = ?3
          `)
          .bind(productName, enabled, product.id)
          .run();

        if (productName !== product.product_name) {
          await writeAudit(env,{
            actorType:"OWNER",category:"PRODUCT",action:"PRODUCT_RENAMED",
            targetType:"PRODUCT",targetId:productCode,
            message:`Product ${product.product_name} diganti nama menjadi ${productName}.`
          });
        }
        if (enabled !== Number(product.enabled)) {
          await writeAudit(env,{
            actorType:"OWNER",category:"PRODUCT",
            action:enabled===1 ? "PRODUCT_ENABLED":"PRODUCT_DISABLED",
            targetType:"PRODUCT",targetId:productCode,
            message:`Product ${productName} ${enabled===1 ? "diaktifkan":"dinonaktifkan"} oleh Owner.`
          });
        }
        return json({
          ok: true,
          message: "PRODUCT UPDATED",
          product: {
            product_id: product.product_code,
            product_name: productName,
            product_type: product.product_type,
            enabled,
          },
        });
      } catch (error) {
        console.error("ADMIN PRODUCT UPDATE ERROR:", error);
        return json({ ok: false, error: "UPDATE PRODUCT FAILED" }, 500);
      }
    }

    // ============================================================
    // ADMIN - PRODUCT LICENSES
    // ============================================================

    if (request.method === "GET" && url.pathname === "/api/admin/product/licenses") {
      try {
        const productCode = normalizeProductCode(url.searchParams.get("product_id"));
        if (!productCode) return json({ ok: false, error: "PRODUCT ID REQUIRED" }, 400);

        const product = await getProductByCode(env, productCode);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const result = await env.DB
          .prepare(`
            SELECT
              l.id,
              l.license_key,
              l.enabled,
              l.expires_at,
              l.max_devices,
              l.created_at,
              l.last_used_at,
              COUNT(d.id) AS device_count
            FROM licenses l
            LEFT JOIN devices d ON d.license_id = l.id
            WHERE l.product_id = ?1
            GROUP BY l.id
            ORDER BY l.created_at DESC
          `)
          .bind(product.id)
          .all();

        return json({
          ok: true,
          product: productPublic(product),
          licenses: result.results || [],
        });
      } catch (error) {
        console.error("ADMIN PRODUCT LICENSE LIST ERROR:", error);
        return json({ ok: false, error: "DATABASE ERROR" }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/admin/product/license") {
      try {
        const productCode = normalizeProductCode(url.searchParams.get("product_id"));
        const licenseKey = normalizeAdminKey(url.searchParams.get("key"));
        if (!productCode || !licenseKey) return json({ ok: false, error: "PRODUCT ID AND KEY REQUIRED" }, 400);

        const product = await getProductByCode(env, productCode);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const license = await env.DB
          .prepare(`
            SELECT id, license_key, enabled, expires_at, max_devices, created_at, last_used_at
            FROM licenses
            WHERE license_key = ?1 AND product_id = ?2
            LIMIT 1
          `)
          .bind(licenseKey, product.id)
          .first();

        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        const devices = await env.DB
          .prepare(`
            SELECT hwid, first_seen_at, last_seen_at
            FROM devices
            WHERE license_id = ?1
            ORDER BY first_seen_at ASC
          `)
          .bind(license.id)
          .all();

        const now = unixNow();
        let daysRemaining = null;
        let expired = false;
        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);
          expired = expiresAt <= now;
          daysRemaining = expired ? 0 : Math.ceil((expiresAt - now) / 86400);
        }

        return json({
          ok: true,
          product: productPublic(product),
          license: {
            license_key: license.license_key,
            enabled: Number(license.enabled),
            expires_at: license.expires_at,
            days_remaining: daysRemaining,
            expired,
            max_devices: Number(license.max_devices) || 0,
            created_at: license.created_at,
            last_used_at: license.last_used_at,
            devices: devices.results || [],
          },
        });
      } catch (error) {
        console.error("ADMIN PRODUCT LICENSE DETAIL ERROR:", error);
        return json({ ok: false, error: "DATABASE ERROR" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/product/create-license") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);

        const productCode = normalizeProductCode(body.product_id);
        const product = productCode ? await getProductByCode(env, productCode) : null;
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        if (Number(product.enabled) !== 1) return json({ ok: false, error: "PRODUCT DISABLED" }, 400);

        const count = Number(body.count ?? 1);
        const maxDevices = Number(body.max_devices ?? 1);
        if (!Number.isInteger(count) || count < 1 || count > 100) return json({ ok: false, error: "COUNT MUST BE BETWEEN 1 AND 100" }, 400);
        if (!Number.isInteger(maxDevices) || maxDevices < 0) return json({ ok: false, error: "INVALID MAX DEVICES" }, 400);

        let expiresAt = null;
        let expiryDays = null;
        if (body.expires_in_days !== null && body.expires_in_days !== undefined) {
          expiryDays = Number(body.expires_in_days);
          if (!Number.isInteger(expiryDays) || expiryDays < 1) return json({ ok: false, error: "INVALID EXPIRY DAYS" }, 400);
          expiresAt = unixNow() + expiryDays * 86400;
        }

        const createdAt = unixNow();
        const keys = await generateUniqueKeys(env, count);
        const statements = keys.map((key) =>
          env.DB.prepare(`
            INSERT INTO licenses (
              license_key, enabled, expires_at, max_devices, created_at, product_id
            ) VALUES (?1, 1, ?2, ?3, ?4, ?5)
          `).bind(key, expiresAt, maxDevices, createdAt, product.id)
        );
        await env.DB.batch(statements);
        await writeAudit(env,{
          actorType:"OWNER",category:"LICENSE",action:"OWNER_LICENSES_CREATED",
          targetType:"PRODUCT",targetId:product.product_code,
          message:`Owner membuat ${count} key untuk product ${product.product_name}.`
        });

        return json({
          ok: true,
          message: "PRODUCT LICENSE CREATED",
          product: productPublic(product),
          licenses: keys.map((key) => ({
            license_key: key,
            enabled: 1,
            expires_at: expiresAt,
            expires_in_days: expiryDays,
            max_devices: maxDevices,
          })),
        });
      } catch (error) {
        console.error("ADMIN PRODUCT LICENSE CREATE ERROR:", error);
        return json({ ok: false, error: "CREATE LICENSE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/product/update-license") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        if (!productCode || !licenseKey) return json({ ok: false, error: "PRODUCT ID AND KEY REQUIRED" }, 400);

        const product = await getProductByCode(env, productCode);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);

        const license = await env.DB
          .prepare(`SELECT id, enabled, expires_at, max_devices FROM licenses WHERE license_key = ?1 AND product_id = ?2 LIMIT 1`)
          .bind(licenseKey, product.id)
          .first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        let newEnabled = Number(license.enabled);
        let newExpiresAt = license.expires_at;
        let newMaxDevices = Number(license.max_devices) || 0;

        if (body.enabled !== undefined) {
          const v = Number(body.enabled);
          if (v !== 0 && v !== 1) return json({ ok: false, error: "ENABLED MUST BE 0 OR 1" }, 400);
          newEnabled = v;
        }
        if (body.max_devices !== undefined) {
          const v = Number(body.max_devices);
          if (!Number.isInteger(v) || v < 0) return json({ ok: false, error: "INVALID MAX DEVICES" }, 400);
          newMaxDevices = v;
        }
        if (body.expiry_action !== undefined) {
          const action = String(body.expiry_action);
          if (action === "unlimited") newExpiresAt = null;
          else if (action === "set_from_now" || action === "add_days") {
            const days = Number(body.expiry_days);
            if (!Number.isInteger(days) || days < 1) return json({ ok: false, error: "INVALID EXPIRY DAYS" }, 400);
            if (action === "set_from_now") newExpiresAt = unixNow() + days * 86400;
            else {
              const now = unixNow();
              const base = license.expires_at !== null && Number(license.expires_at) > now ? Number(license.expires_at) : now;
              newExpiresAt = base + days * 86400;
            }
          } else return json({ ok: false, error: "INVALID EXPIRY ACTION" }, 400);
        }

        await env.DB
          .prepare(`UPDATE licenses SET enabled = ?1, expires_at = ?2, max_devices = ?3 WHERE id = ?4`)
          .bind(newEnabled, newExpiresAt, newMaxDevices, license.id)
          .run();
        await writeAudit(env,{
          actorType:"OWNER",category:"LICENSE",action:"OWNER_LICENSE_UPDATED",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Owner memperbarui key ${shortAuditId(licenseKey)} pada product ${product.product_name}.`
        });

        return json({ ok: true, message: "LICENSE UPDATED" });
      } catch (error) {
        console.error("ADMIN PRODUCT LICENSE UPDATE ERROR:", error);
        return json({ ok: false, error: "UPDATE LICENSE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/product/reset-device") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        if (!productCode || !licenseKey) return json({ ok: false, error: "PRODUCT ID AND KEY REQUIRED" }, 400);

        const product = await getProductByCode(env, productCode);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        const license = await env.DB
          .prepare(`SELECT id FROM licenses WHERE license_key = ?1 AND product_id = ?2 LIMIT 1`)
          .bind(licenseKey, product.id)
          .first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        let result;
        if (body.all === true) {
          result = await env.DB.prepare(`DELETE FROM devices WHERE license_id = ?1`).bind(license.id).run();
        } else {
          const hwid = String(body.hwid || "").trim();
          if (!hwid) return json({ ok: false, error: "HWID REQUIRED" }, 400);
          result = await env.DB.prepare(`DELETE FROM devices WHERE license_id = ?1 AND hwid = ?2`).bind(license.id, hwid).run();
        }

        await writeAudit(env,{
          actorType:"OWNER",category:"LICENSE",action:"OWNER_LICENSE_DEVICE_RESET",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Owner mereset binding device key ${shortAuditId(licenseKey)} pada product ${product.product_name}.`
        });
        return json({ ok: true, message: "DEVICE RESET", removed: Number(result.meta?.changes || 0) });
      } catch (error) {
        console.error("ADMIN PRODUCT RESET ERROR:", error);
        return json({ ok: false, error: "RESET DEVICE FAILED" }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/product/delete-license") {
      try {
        const body = await readJson(request);
        if (!body) return json({ ok: false, error: "INVALID JSON" }, 400);
        const productCode = normalizeProductCode(body.product_id);
        const licenseKey = normalizeAdminKey(body.license_key);
        if (!productCode || !licenseKey) return json({ ok: false, error: "PRODUCT ID AND KEY REQUIRED" }, 400);

        const product = await getProductByCode(env, productCode);
        if (!product) return json({ ok: false, error: "PRODUCT NOT FOUND" }, 404);
        const license = await env.DB
          .prepare(`SELECT id FROM licenses WHERE license_key = ?1 AND product_id = ?2 LIMIT 1`)
          .bind(licenseKey, product.id)
          .first();
        if (!license) return json({ ok: false, error: "LICENSE NOT FOUND" }, 404);

        await env.DB.batch([
          env.DB.prepare(`DELETE FROM devices WHERE license_id = ?1`).bind(license.id),
          env.DB.prepare(`DELETE FROM licenses WHERE id = ?1`).bind(license.id),
        ]);

        await writeAudit(env,{
          actorType:"OWNER",category:"LICENSE",action:"OWNER_LICENSE_DELETED",
          targetType:"LICENSE",targetId:licenseKey,
          message:`Owner menghapus key ${shortAuditId(licenseKey)} dari product ${product.product_name}.`
        });
        return json({ ok: true, message: "LICENSE DELETED" });
      } catch (error) {
        console.error("ADMIN PRODUCT DELETE ERROR:", error);
        return json({ ok: false, error: "DELETE LICENSE FAILED" }, 500);
      }
    }

    // ============================================================
    // ADMIN - LIST LICENSES
    // ============================================================

    if (
      request.method === "GET" &&
      url.pathname === "/api/admin/list"
    ) {
      try {
        const result = await env.DB
          .prepare(`
            SELECT
              l.id,
              l.license_key,
              l.enabled,
              l.expires_at,
              l.max_devices,
              l.created_at,
              l.last_used_at,
              COUNT(d.id) AS device_count
            FROM licenses l
            LEFT JOIN devices d
              ON d.license_id = l.id
            WHERE l.product_id IS NULL
            GROUP BY l.id
            ORDER BY l.created_at DESC
          `)
          .all();

        return json({
          ok: true,
          licenses: result.results || [],
        });
      } catch (error) {
        console.error("ADMIN LIST ERROR:", error);

        return json(
          {
            ok: false,
            error: "DATABASE ERROR",
          },
          500
        );
      }
    }


    // ============================================================
    // ADMIN - LICENSE DETAIL / SEARCH
    // ============================================================

    if (
      request.method === "GET" &&
      url.pathname === "/api/admin/license"
    ) {
      try {
        const licenseKey = normalizeAdminKey(
          url.searchParams.get("key")
        );

        if (!licenseKey) {
          return json(
            {
              ok: false,
              error: "LICENSE KEY REQUIRED",
            },
            400
          );
        }

        const license = await env.DB
          .prepare(`
            SELECT
              id,
              license_key,
              enabled,
              expires_at,
              max_devices,
              created_at,
              last_used_at
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(licenseKey)
          .first();

        if (!license) {
          return json(
            {
              ok: false,
              error: "LICENSE NOT FOUND",
            },
            404
          );
        }

        const devices = await env.DB
          .prepare(`
            SELECT
              hwid,
              first_seen_at,
              last_seen_at
            FROM devices
            WHERE license_id = ?1
            ORDER BY first_seen_at ASC
          `)
          .bind(license.id)
          .all();

        const now = unixNow();

        let daysRemaining = null;
        let expired = false;

        if (license.expires_at !== null) {
          const expiresAt = Number(license.expires_at);

          expired = expiresAt <= now;

          daysRemaining = expired
            ? 0
            : Math.ceil((expiresAt - now) / 86400);
        }

        return json({
          ok: true,
          license: {
            license_key: license.license_key,
            enabled: Number(license.enabled),
            expires_at: license.expires_at,
            days_remaining: daysRemaining,
            expired,
            max_devices: Number(license.max_devices) || 0,
            created_at: license.created_at,
            last_used_at: license.last_used_at,
            devices: devices.results || [],
          },
        });
      } catch (error) {
        console.error("ADMIN DETAIL ERROR:", error);

        return json(
          {
            ok: false,
            error: "DATABASE ERROR",
          },
          500
        );
      }
    }


    // ============================================================
    // ADMIN - CREATE LICENSE
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/create"
    ) {
      try {
        const body = await readJson(request);

        if (!body) {
          return json(
            {
              ok: false,
              error: "INVALID JSON",
            },
            400
          );
        }

        const count = Number(body.count ?? 1);
        const maxDevices = Number(body.max_devices ?? 1);

        if (
          !Number.isInteger(count) ||
          count < 1 ||
          count > 100
        ) {
          return json(
            {
              ok: false,
              error: "COUNT MUST BE BETWEEN 1 AND 100",
            },
            400
          );
        }

        if (
          !Number.isInteger(maxDevices) ||
          maxDevices < 0
        ) {
          return json(
            {
              ok: false,
              error: "INVALID MAX DEVICES",
            },
            400
          );
        }

        let expiresAt = null;
        let expiryDays = null;

        if (body.expires_in_days !== null &&
            body.expires_in_days !== undefined) {

          expiryDays = Number(body.expires_in_days);

          if (
            !Number.isInteger(expiryDays) ||
            expiryDays < 1
          ) {
            return json(
              {
                ok: false,
                error: "INVALID EXPIRY DAYS",
              },
              400
            );
          }

          expiresAt =
            unixNow() + (expiryDays * 86400);
        }

        const createdAt = unixNow();

        const keys = await generateUniqueKeys(
          env,
          count
        );

        const statements = keys.map((key) =>
          env.DB
            .prepare(`
              INSERT INTO licenses (
                license_key,
                enabled,
                expires_at,
                max_devices,
                created_at,
                product_id
              )
              VALUES (?1, 1, ?2, ?3, ?4, NULL)
            `)
            .bind(
              key,
              expiresAt,
              maxDevices,
              createdAt
            )
        );

        await env.DB.batch(statements);

        return json({
          ok: true,
          message: "LICENSE CREATED",
          licenses: keys.map((key) => ({
            license_key: key,
            enabled: 1,
            expires_at: expiresAt,
            expires_in_days: expiryDays,
            max_devices: maxDevices,
          })),
        });
      } catch (error) {
        console.error("ADMIN CREATE ERROR:", error);

        return json(
          {
            ok: false,
            error: "CREATE LICENSE FAILED",
          },
          500
        );
      }
    }


    // ============================================================
    // ADMIN - UPDATE LICENSE
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/update"
    ) {
      try {
        const body = await readJson(request);

        if (!body) {
          return json(
            {
              ok: false,
              error: "INVALID JSON",
            },
            400
          );
        }

        const licenseKey = normalizeAdminKey(
          body.license_key
        );

        if (!licenseKey) {
          return json(
            {
              ok: false,
              error: "LICENSE KEY REQUIRED",
            },
            400
          );
        }

        const license = await env.DB
          .prepare(`
            SELECT
              id,
              enabled,
              expires_at,
              max_devices
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(licenseKey)
          .first();

        if (!license) {
          return json(
            {
              ok: false,
              error: "LICENSE NOT FOUND",
            },
            404
          );
        }

        let newEnabled = Number(license.enabled);
        let newExpiresAt = license.expires_at;
        let newMaxDevices =
          Number(license.max_devices) || 0;

        // ----------------------------
        // ENABLE / DISABLE
        // ----------------------------

        if (body.enabled !== undefined) {
          const enabled = Number(body.enabled);

          if (enabled !== 0 && enabled !== 1) {
            return json(
              {
                ok: false,
                error: "ENABLED MUST BE 0 OR 1",
              },
              400
            );
          }

          newEnabled = enabled;
        }

        // ----------------------------
        // MAX DEVICES
        // ----------------------------

        if (body.max_devices !== undefined) {
          const maxDevices =
            Number(body.max_devices);

          if (
            !Number.isInteger(maxDevices) ||
            maxDevices < 0
          ) {
            return json(
              {
                ok: false,
                error: "INVALID MAX DEVICES",
              },
              400
            );
          }

          newMaxDevices = maxDevices;
        }

        // ----------------------------
        // EXPIRY
        // ----------------------------

        if (body.expiry_action !== undefined) {
          const action =
            String(body.expiry_action);

          if (action === "unlimited") {
            newExpiresAt = null;
          }

          else if (action === "set_from_now") {
            const days =
              Number(body.expiry_days);

            if (
              !Number.isInteger(days) ||
              days < 1
            ) {
              return json(
                {
                  ok: false,
                  error: "INVALID EXPIRY DAYS",
                },
                400
              );
            }

            newExpiresAt =
              unixNow() + (days * 86400);
          }

          else if (action === "add_days") {
            const days =
              Number(body.expiry_days);

            if (
              !Number.isInteger(days) ||
              days < 1
            ) {
              return json(
                {
                  ok: false,
                  error: "INVALID EXPIRY DAYS",
                },
                400
              );
            }

            const now = unixNow();

            let base = now;

            if (
              license.expires_at !== null &&
              Number(license.expires_at) > now
            ) {
              base = Number(
                license.expires_at
              );
            }

            newExpiresAt =
              base + (days * 86400);
          }

          else {
            return json(
              {
                ok: false,
                error: "INVALID EXPIRY ACTION",
              },
              400
            );
          }
        }

        await env.DB
          .prepare(`
            UPDATE licenses
            SET
              enabled = ?1,
              expires_at = ?2,
              max_devices = ?3
            WHERE id = ?4
          `)
          .bind(
            newEnabled,
            newExpiresAt,
            newMaxDevices,
            license.id
          )
          .run();

        return json({
          ok: true,
          message: "LICENSE UPDATED",
          license: {
            license_key: licenseKey,
            enabled: newEnabled,
            expires_at: newExpiresAt,
            max_devices: newMaxDevices,
          },
        });
      } catch (error) {
        console.error("ADMIN UPDATE ERROR:", error);

        return json(
          {
            ok: false,
            error: "UPDATE LICENSE FAILED",
          },
          500
        );
      }
    }


    // ============================================================
    // ADMIN - RESET DEVICE / HWID
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/reset-device"
    ) {
      try {
        const body = await readJson(request);

        if (!body) {
          return json(
            {
              ok: false,
              error: "INVALID JSON",
            },
            400
          );
        }

        const licenseKey = normalizeAdminKey(
          body.license_key
        );

        if (!licenseKey) {
          return json(
            {
              ok: false,
              error: "LICENSE KEY REQUIRED",
            },
            400
          );
        }

        const license = await env.DB
          .prepare(`
            SELECT id
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(licenseKey)
          .first();

        if (!license) {
          return json(
            {
              ok: false,
              error: "LICENSE NOT FOUND",
            },
            404
          );
        }

        let result;

        if (body.all === true) {
          result = await env.DB
            .prepare(`
              DELETE FROM devices
              WHERE license_id = ?1
            `)
            .bind(license.id)
            .run();
        } else {
          const hwid = String(
            body.hwid || ""
          ).trim();

          if (!hwid) {
            return json(
              {
                ok: false,
                error: "HWID REQUIRED",
              },
              400
            );
          }

          result = await env.DB
            .prepare(`
              DELETE FROM devices
              WHERE license_id = ?1
                AND hwid = ?2
            `)
            .bind(
              license.id,
              hwid
            )
            .run();
        }

        const removed = Number(
          result?.meta?.changes || 0
        );

        return json({
          ok: true,
          message: "DEVICE RESET SUCCESSFUL",
          removed,
        });
      } catch (error) {
        console.error(
          "ADMIN RESET DEVICE ERROR:",
          error
        );

        return json(
          {
            ok: false,
            error: "RESET DEVICE FAILED",
          },
          500
        );
      }
    }


    // ============================================================
    // ADMIN - DELETE LICENSE
    // ============================================================

    if (
      request.method === "POST" &&
      url.pathname === "/api/admin/delete"
    ) {
      try {
        const body = await readJson(request);

        if (!body) {
          return json(
            {
              ok: false,
              error: "INVALID JSON",
            },
            400
          );
        }

        const licenseKey = normalizeAdminKey(
          body.license_key
        );

        if (!licenseKey) {
          return json(
            {
              ok: false,
              error: "LICENSE KEY REQUIRED",
            },
            400
          );
        }

        const license = await env.DB
          .prepare(`
            SELECT id
            FROM licenses
            WHERE license_key = ?1
              AND product_id IS NULL
            LIMIT 1
          `)
          .bind(licenseKey)
          .first();

        if (!license) {
          return json(
            {
              ok: false,
              error: "LICENSE NOT FOUND",
            },
            404
          );
        }

        await env.DB.batch([
          env.DB
            .prepare(`
              DELETE FROM devices
              WHERE license_id = ?1
            `)
            .bind(license.id),

          env.DB
            .prepare(`
              DELETE FROM licenses
              WHERE id = ?1
            `)
            .bind(license.id),
        ]);

        return json({
          ok: true,
          message: "LICENSE DELETED",
        });
      } catch (error) {
        console.error(
          "ADMIN DELETE ERROR:",
          error
        );

        return json(
          {
            ok: false,
            error: "DELETE LICENSE FAILED",
          },
          500
        );
      }
    }


    // ============================================================
    // NOT FOUND
    // ============================================================

    return new Response("Not Found", {
      status: 404,
      headers: {
        "content-type":
          "text/plain; charset=UTF-8",
      },
    });
  },
};


// ============================================================
// ADMIN AUTH
// ============================================================

function isAdmin(request, env) {
  const configuredSecret =
    String(env.ADMIN_SECRET || "");

  if (!configuredSecret) {
    return false;
  }

  const suppliedSecret =
    request.headers.get("X-Admin-Key") || "";

  return suppliedSecret === configuredSecret;
}


// ============================================================
// KEY GENERATOR
// ============================================================

async function generateUniqueKeys(env, count) {
  const keys = [];
  const used = new Set();

  while (keys.length < count) {
    const candidate =
      KEY_PREFIX + randomKeyPart();

    if (used.has(candidate)) {
      continue;
    }

    const exists = await env.DB
      .prepare(`
        SELECT id
        FROM licenses
        WHERE license_key = ?1
        LIMIT 1
      `)
      .bind(candidate)
      .first();

    if (exists) {
      continue;
    }

    used.add(candidate);
    keys.push(candidate);
  }

  return keys;
}


function randomKeyPart() {
  const bytes = new Uint8Array(
    KEY_RANDOM_LENGTH
  );

  crypto.getRandomValues(bytes);

  let result = "";

  for (let i = 0; i < bytes.length; i++) {
    result += KEY_CHARSET[
      bytes[i] % KEY_CHARSET.length
    ];
  }

  return result;
}



// ============================================================
// PRODUCT HELPERS
// ============================================================

function normalizeProductCode(value) {
  const code = String(value || "").trim();
  return code || null;
}

async function getProductByCode(env, productCode) {
  return await env.DB
    .prepare(`
      SELECT id, product_code, product_name, product_type, enabled, created_at, customer_id
      FROM products
      WHERE product_code = ?1
      LIMIT 1
    `)
    .bind(productCode)
    .first();
}

function productPublic(product) {
  return {
    product_id: product.product_code,
    product_name: product.product_name,
    product_type: product.product_type,
    enabled: Number(product.enabled),
    created_at: product.created_at,
  };
}


// ============================================================
// CUSTOMER HELPERS
// ============================================================

function normalizeCustomerCode(value) {
  const code = String(value || "").trim();
  return code || null;
}

function customerPublic(customer) {
  const now = unixNow();
  const expiresAt = Number(customer.subscription_expires_at || 0);

  let subscriptionStatus = "NOT_CONFIGURED";
  let subscriptionDaysRemaining = 0;

  if (expiresAt > 0) {
    if (expiresAt <= now) {
      subscriptionStatus = "EXPIRED";
      subscriptionDaysRemaining = 0;
    } else {
      subscriptionStatus = "ACTIVE";
      subscriptionDaysRemaining = Math.ceil((expiresAt - now) / 86400);
    }
  }

  if (Number(customer.enabled) !== 1) {
    subscriptionStatus = "DISABLED";
  }

  return {
    customer_id: customer.customer_code,
    customer_name: customer.customer_name,
    enabled: Number(customer.enabled),
    subscription_expires_at: customer.subscription_expires_at,
    subscription_status: subscriptionStatus,
    subscription_days_remaining: subscriptionDaysRemaining,
    max_products: Number(customer.max_products),
    max_total_keys: Number(customer.max_total_keys),
    max_keys_per_product: Number(customer.max_keys_per_product),
    max_active_keys: Number(customer.max_active_keys),
    max_devices_per_key: Number(customer.max_devices_per_key),
    max_license_days: Number(customer.max_license_days),
    create_limit_per_day: Number(customer.create_limit_per_day),
    reset_limit_per_day: Number(customer.reset_limit_per_day),
    created_at: customer.created_at,
    updated_at: customer.updated_at,
  };
}


function shortAuditId(value, length = 12) {
  const text=String(value || "");
  if (!text) return "-";
  return text.length <= length ? text : text.slice(0,length) + "...";
}

async function writeAudit(env, {
  actorType="OWNER",
  actorId=null,
  category="SECURITY",
  action="UNKNOWN",
  targetType=null,
  targetId=null,
  message="",
  details=null,
}={}) {
  try {
    if (!message) return;
    await env.DB.prepare(`
      INSERT INTO audit_logs (
        actor_type, actor_id, category, action,
        target_type, target_id, message, details, created_at
      ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
    `).bind(
      String(actorType),
      actorId == null ? null : String(actorId),
      String(category).toUpperCase(),
      String(action),
      targetType == null ? null : String(targetType),
      targetId == null ? null : String(targetId),
      String(message),
      details == null ? null : JSON.stringify(details),
      unixNow()
    ).run();
  } catch (error) {
    console.error("AUDIT WRITE ERROR:",error);
  }
}

async function getCustomerByCode(env, code) {
  return await env.DB.prepare(`
    SELECT * FROM customers
    WHERE customer_code = ?1
    LIMIT 1
  `).bind(code).first();
}

async function getCustomerProductByCode(env, customerId, productCode) {
  return await env.DB.prepare(`
    SELECT id, product_code, product_name, product_type, enabled, created_at, customer_id
    FROM products
    WHERE product_code = ?1 AND customer_id = ?2
    LIMIT 1
  `).bind(productCode, customerId).first();
}

function isLimited(value) {
  return Number(value) > 0;
}

function normalizeCustomerLimits(body) {
  const names = [
    "max_products", "max_total_keys", "max_keys_per_product", "max_active_keys",
    "max_devices_per_key", "max_license_days", "create_limit_per_day", "reset_limit_per_day",
  ];
  const out = { ok: true };
  for (const name of names) {
    const v = Number(body[name] ?? 0);
    if (!Number.isInteger(v) || v < 0) {
      return { ok: false, error: `INVALID ${name.toUpperCase()}` };
    }
    out[name] = v;
  }
  return out;
}

async function countCustomerProducts(env, customerId) {
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS total FROM products WHERE customer_id=?1
  `).bind(customerId).first();
  return Number(row?.total || 0);
}

async function countCustomerTotalKeys(env, customerId) {
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM licenses l
    JOIN products p ON p.id = l.product_id
    WHERE p.customer_id=?1
  `).bind(customerId).first();
  return Number(row?.total || 0);
}

async function countCustomerActiveKeys(env, customerId) {
  const now = unixNow();
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM licenses l
    JOIN products p ON p.id = l.product_id
    WHERE p.customer_id=?1
      AND l.enabled=1
      AND (l.expires_at IS NULL OR l.expires_at > ?2)
  `).bind(customerId, now).first();
  return Number(row?.total || 0);
}

async function countProductKeys(env, productId) {
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS total FROM licenses WHERE product_id=?1
  `).bind(productId).first();
  return Number(row?.total || 0);
}

function utcUsageDate() {
  return new Date().toISOString().slice(0, 10);
}

async function getCustomerDailyUsage(env, customerId) {
  const day = utcUsageDate();
  const row = await env.DB.prepare(`
    SELECT keys_created, hwid_resets
    FROM customer_daily_usage
    WHERE customer_id=?1 AND usage_date=?2
    LIMIT 1
  `).bind(customerId, day).first();
  return row || { keys_created: 0, hwid_resets: 0 };
}

async function incrementCustomerDailyUsage(env, customerId, field, amount) {
  if (!["keys_created", "hwid_resets"].includes(field)) {
    throw new Error("INVALID USAGE FIELD");
  }
  const day = utcUsageDate();
  await env.DB.prepare(`
    INSERT INTO customer_daily_usage (customer_id, usage_date, keys_created, hwid_resets)
    VALUES (?1, ?2, ?3, ?4)
    ON CONFLICT(customer_id, usage_date) DO UPDATE SET
      keys_created = keys_created + excluded.keys_created,
      hwid_resets = hwid_resets + excluded.hwid_resets
  `).bind(
    customerId,
    day,
    field === "keys_created" ? amount : 0,
    field === "hwid_resets" ? amount : 0
  ).run();
}

async function getCustomerUsageSummary(env, customer) {
  const daily = await getCustomerDailyUsage(env, customer.id);
  return {
    products: await countCustomerProducts(env, customer.id),
    total_keys: await countCustomerTotalKeys(env, customer.id),
    active_keys: await countCustomerActiveKeys(env, customer.id),
    keys_created_today: Number(daily.keys_created || 0),
    hwid_resets_today: Number(daily.hwid_resets || 0),
  };
}

async function checkCustomerCreateQuota(env, customer, productId, count, maxDevices, expiryDays) {
  if (isLimited(customer.max_devices_per_key) &&
      (maxDevices === 0 || maxDevices > Number(customer.max_devices_per_key))) {
    return "CUSTOMER DEVICE LIMIT";
  }

  if (expiryDays === null) {
    if (isLimited(customer.max_license_days)) return "UNLIMITED EXPIRY NOT ALLOWED";
  } else if (isLimited(customer.max_license_days) &&
             expiryDays > Number(customer.max_license_days)) {
    return "CUSTOMER LICENSE DAY LIMIT";
  }

  const [total, perProduct, active, daily] = await Promise.all([
    countCustomerTotalKeys(env, customer.id),
    countProductKeys(env, productId),
    countCustomerActiveKeys(env, customer.id),
    getCustomerDailyUsage(env, customer.id),
  ]);

  if (isLimited(customer.max_total_keys) &&
      total + count > Number(customer.max_total_keys)) {
    return "CUSTOMER TOTAL KEY LIMIT";
  }
  if (isLimited(customer.max_keys_per_product) &&
      perProduct + count > Number(customer.max_keys_per_product)) {
    return "CUSTOMER PRODUCT KEY LIMIT";
  }
  if (isLimited(customer.max_active_keys) &&
      active + count > Number(customer.max_active_keys)) {
    return "CUSTOMER ACTIVE KEY LIMIT";
  }
  if (isLimited(customer.create_limit_per_day) &&
      Number(daily.keys_created || 0) + count > Number(customer.create_limit_per_day)) {
    return "CUSTOMER DAILY CREATE LIMIT";
  }
  return null;
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function authenticateCustomer(request, env) {
  const code = normalizeCustomerCode(request.headers.get("X-Customer-Code"));
  const credential = String(request.headers.get("X-Customer-Credential") || "");
  if (!code || !credential) return null;
  const customer = await getCustomerByCode(env, code);
  if (!customer) return null;
  const suppliedHash = await sha256Hex(credential);
  return suppliedHash === String(customer.credential_hash || "") ? customer : null;
}


function normalizeDeviceLabel(value) {
  const text = String(value || "").trim().replace(/\s+/g, " ");
  return text.slice(0, 120);
}

async function requireCustomerAccess(request, env) {
  const customer = await authenticateCustomer(request, env);
  if (!customer) {
    return {
      ok: false,
      error: "UNAUTHORIZED",
      status: "UNAUTHORIZED",
      httpStatus: 401,
    };
  }

  if (Number(customer.enabled) !== 1) {
    return {
      ok: false,
      error: "CUSTOMER DISABLED",
      status: "DISABLED",
      httpStatus: 403,
    };
  }

  // Subscription uses SERVER time only.
  // NULL/0 is never treated as unlimited in Subscription V1.
  const now = unixNow();
  const expiresAt = Number(customer.subscription_expires_at || 0);

  if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
    return {
      ok: false,
      error: "CUSTOMER SUBSCRIPTION NOT CONFIGURED",
      status: "NOT_CONFIGURED",
      httpStatus: 403,
    };
  }

  if (expiresAt <= now) {
    return {
      ok: false,
      error: "CUSTOMER SUBSCRIPTION EXPIRED",
      status: "EXPIRED",
      httpStatus: 403,
    };
  }

  const suppliedDevice = String(
    request.headers.get("X-Customer-Device") || ""
  ).trim();

  if (!suppliedDevice || suppliedDevice.length < 16 || suppliedDevice.length > 256) {
    return {
      ok: false,
      error: "CUSTOMER DEVICE REQUIRED",
      status: "DEVICE_REQUIRED",
      httpStatus: 403,
    };
  }

  const deviceHash = await sha256Hex(suppliedDevice);
  const deviceLabel = normalizeDeviceLabel(
    request.headers.get("X-Customer-Device-Label")
  );

  let device = await env.DB.prepare(`
    SELECT id, device_hash, device_label, enabled, first_seen_at, last_seen_at
    FROM customer_admin_devices
    WHERE customer_id=?1 AND device_hash=?2
    LIMIT 1
  `).bind(customer.id, deviceHash).first();

  if (!device) {
    const countRow = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM customer_admin_devices
      WHERE customer_id=?1
    `).bind(customer.id).first();

    const existingCount = Number(countRow?.total || 0);
    const autoApprove = existingCount === 0 ? 1 : 0;

    await env.DB.prepare(`
      INSERT INTO customer_admin_devices (
        customer_id, device_hash, device_label, enabled,
        first_seen_at, last_seen_at
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    `).bind(
      customer.id,
      deviceHash,
      deviceLabel || null,
      autoApprove,
      now,
      now
    ).run();

    if (autoApprove !== 1) {
      await writeAudit(env,{
        actorType:"CUSTOMER",actorId:customer.customer_code,
        category:"SECURITY",action:"NEW_CUSTOMER_DEVICE_PENDING",
        targetType:"CUSTOMER_DEVICE",targetId:deviceHash,
        message:`Device baru mencoba membuka Customer Admin milik ${customer.customer_name} dan menunggu persetujuan Owner. Device: ${shortAuditId(deviceHash)}.`
      });
      return {
        ok: false,
        error: "CUSTOMER DEVICE NOT APPROVED",
        status: "DEVICE_PENDING",
        httpStatus: 403,
      };
    }

    device = {
      device_hash: deviceHash,
      device_label: deviceLabel,
      enabled: 1,
    };
  } else {
    await env.DB.prepare(`
      UPDATE customer_admin_devices
      SET last_seen_at=?1,
          device_label=CASE WHEN ?2<>'' THEN ?2 ELSE device_label END
      WHERE id=?3
    `).bind(now, deviceLabel, device.id).run();

    if (Number(device.enabled) !== 1) {
      return {
        ok: false,
        error: "CUSTOMER DEVICE BLOCKED",
        status: "DEVICE_BLOCKED",
        httpStatus: 403,
      };
    }
  }

  return {
    ok: true,
    customer,
    device_hash: deviceHash,
  };
}

function randomText(length, charset) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += charset[b % charset.length];
  return out;
}

async function generateUniqueCustomerCode(env) {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  while (true) {
    const code = "CUS_" + randomText(10, charset);
    const exists = await env.DB.prepare(
      `SELECT id FROM customers WHERE customer_code=?1 LIMIT 1`
    ).bind(code).first();
    if (!exists) return code;
  }
}

function generateCustomerCredential() {
  const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  return "cust_" + randomText(40, charset);
}

// ============================================================
// ADMIN KEY NORMALIZATION
// ============================================================

function normalizeAdminKey(value) {
  const key =
    String(value || "")
      .trim();

  return key || null;
}


// ============================================================
// JSON BODY
// ============================================================

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}


// ============================================================
// RESPONSE HELPERS
// ============================================================

function text(value) {
  return new Response(value, {
    status: 200,
    headers: {
      "content-type":
        "text/plain; charset=UTF-8",
    },
  });
}


function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=UTF-8",
      },
    }
  );
}


// ============================================================
// TIME
// ============================================================

function unixNow() {
  return Math.floor(
    Date.now() / 1000
  );
}



// ============================================================
// MASTER TOKEN - MD5 HEX
// Pure JS implementation because WebCrypto does not guarantee MD5.
// ============================================================

function md5Hex(input) {
  const bytes = new TextEncoder().encode(String(input));
  const originalBits = bytes.length * 8;
  const paddedLength = (((bytes.length + 8) >>> 6) + 1) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(bytes);
  buffer[bytes.length] = 0x80;

  let bitLen = BigInt(originalBits);
  for (let i = 0; i < 8; i++) {
    buffer[paddedLength - 8 + i] = Number(bitLen & 0xffn);
    bitLen >>= 8n;
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  const s = [
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
  ];

  const k = Array.from({ length: 64 }, (_, i) =>
    Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0
  );

  const leftRotate = (x, n) =>
    ((x << n) | (x >>> (32 - n))) >>> 0;

  for (let offset = 0; offset < buffer.length; offset += 64) {
    const m = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      m[i] = (
        buffer[j] |
        (buffer[j + 1] << 8) |
        (buffer[j + 2] << 16) |
        (buffer[j + 3] << 24)
      ) >>> 0;
    }

    let a = a0, b = b0, c = c0, d = d0;

    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }

      const nextD = c;
      const nextC = b;
      const sum = (a + f + k[i] + m[g]) >>> 0;
      const nextB = (b + leftRotate(sum, s[i])) >>> 0;
      a = d;
      d = nextD;
      c = nextC;
      b = nextB;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const wordHexLE = (word) => {
    let out = "";
    for (let i = 0; i < 4; i++) {
      out += ((word >>> (i * 8)) & 0xff)
        .toString(16)
        .padStart(2, "0");
    }
    return out;
  };

  return wordHexLE(a0) + wordHexLE(b0) +
         wordHexLE(c0) + wordHexLE(d0);
}

// ============================================================
// LUA SIGNATURE
//
// PENTING:
// "NOX" dan "mod" adalah material protokol.
// Jangan diubah hanya karena branding.
// ============================================================

function generateSign(
  key,
  hwid,
  timestamp,
  nonce
) {
  const raw =
    key +
    "NOX" +
    hwid +
    "mod" +
    String(timestamp) +
    String(nonce);

  const bytes =
    new TextEncoder().encode(raw);

  let hash = 5381 >>> 0;

  for (const byte of bytes) {
    hash =
      (Math.imul(hash, 33) + byte) >>> 0;
  }

  return String(
    Math.floor(
      hash % 2147483647
    )
  );
}


// ============================================================
// PRODUCT LUA SIGNATURE - PROTOCOL P1
// PRODUCT_ID is part of the signed material.
// ============================================================

function generateProductSign(productCode, key, hwid, timestamp, nonce) {
  const raw =
    "P1|" +
    productCode + "|" +
    key + "|" +
    hwid + "|" +
    String(timestamp) + "|" +
    String(nonce) + "|" +
    "NOX|mod";

  const bytes = new TextEncoder().encode(raw);
  let hash = 5381 >>> 0;

  for (const byte of bytes) {
    hash = (Math.imul(hash, 33) + byte) >>> 0;
  }

  return String(Math.floor(hash % 2147483647));
}
