const { createClient } = require("@supabase/supabase-js");

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return { statusCode: 400, headers, body: JSON.stringify({ ok: false }) };
  }

  // Verify client secret
  const { data: secretRow } = await supabase
    .from("config")
    .select("value")
    .eq("key", "client_secret")
    .single();

  if (!secretRow || body.clientSecret !== secretRow.value) {
    return { statusCode: 403, headers, body: JSON.stringify({ ok: false, error: "Unauthorized" }) };
  }

  const action = body.action;

  try {
    // ── Get config values ──
    async function getConfig(key) {
      const { data } = await supabase.from("config").select("value").eq("key", key).single();
      return data ? data.value : null;
    }

    // ── Verify master passkey ──
    if (action === "verify") {
      const master = await getConfig("master_passkey");
      return { statusCode: 200, headers, body: JSON.stringify({ ok: body.passkey === master }) };
    }

    // ── Get chat passkey ──
    if (action === "getPasskey") {
      const chatPasskey = await getConfig("chat_passkey");
      const chatExpiry = await getConfig("chat_expiry");
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, chatPasskey, chatExpiry }) };
    }

    // ── Save passkey ──
    if (action === "savePasskey") {
      const master = await getConfig("master_passkey");
      if (body.masterPasskey !== master) {
        return { statusCode: 403, headers, body: JSON.stringify({ ok: false }) };
      }
      await supabase.from("config").update({ value: body.chatPasskey }).eq("key", "chat_passkey");
      await supabase.from("config").update({ value: body.chatExpiry }).eq("key", "chat_expiry");
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Verify personal key ──
    if (action === "verifyPersonalKey") {
      const n = (body.username || "").toLowerCase().trim();
      let keyName = null;
      if (["istopx","jacob","jacob ulrich"].includes(n)) keyName = "master_passkey";
      else if (["sam","samuel","samuel harms","sam harms","dr. pepper guy","dr pepper guy","coke guy"].includes(n)) keyName = "sam_key";
      else if (["isaac","isaac price"].includes(n)) keyName = "isaac_key";
      if (!keyName) return { statusCode: 200, headers, body: JSON.stringify({ ok: false }) };
      const expected = await getConfig(keyName);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: body.personalKey === expected }) };
    }

    // ── Get personal keys (admin) ──
    if (action === "getPersonalKeys") {
      const samKey = await getConfig("sam_key");
      const isaacKey = await getConfig("isaac_key");
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, samKey, isaacKey }) };
    }

    // ── Save personal key ──
    if (action === "savePersonalKey") {
      const master = await getConfig("master_passkey");
      if (body.masterPasskey !== master) {
        return { statusCode: 403, headers, body: JSON.stringify({ ok: false }) };
      }
      const keyName = body.person === "sam" ? "sam_key" : "isaac_key";
      await supabase.from("config").update({ value: body.personalKey }).eq("key", keyName);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Log session ──
    if (action === "logSession") {
      await supabase.from("sessions").insert({ username: body.username, model: body.model || "", cost: 0 });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Log flag ──
    if (action === "logFlag") {
      await supabase.from("flags").insert({
        username: body.username,
        flag_type: body.flagType,
        severity: body.severity,
        message: (body.message || "").substring(0, 500),
      });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Get flags (admin) ──
    if (action === "getFlags") {
      const { data } = await supabase
        .from("flags")
        .select("*")
        .eq("archived", false)
        .order("created_at", { ascending: false });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, flags: data || [] }) };
    }

    // ── Clear flag ──
    if (action === "clearFlag") {
      await supabase.from("flags").delete().eq("id", body.flagId);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Clear all flags ──
    if (action === "clearAllFlags") {
      await supabase.from("flags").delete().eq("archived", false);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Archive flag ──
    if (action === "archiveFlag") {
      await supabase.from("flags").update({ archived: true, action_taken: body.actionTaken || false }).eq("id", body.flagId);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Get archive ──
    if (action === "getArchive") {
      const { data } = await supabase
        .from("flags")
        .select("*")
        .eq("archived", true)
        .order("created_at", { ascending: false });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, flags: data || [] }) };
    }

    // ── Get sessions ──
    if (action === "getSessions") {
      const { data } = await supabase
        .from("sessions")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(100);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, sessions: data || [] }) };
    }

    // ── Chat messages ──
    if (action === "getChatMessages") {
      const username = body.username || "";
      const roomId = body.roomId || "global";
      const n = username.toLowerCase().trim();
      const isAdmin = ["istopx","jacob","jacob ulrich"].includes(n);
      const isSam = ["sam","samuel","samuel harms","sam harms","dr. pepper guy","dr pepper guy","coke guy"].includes(n);
      const isIsaac = ["isaac","isaac price"].includes(n);

      // Block jacob from sam_isaac dm
      if (roomId === "dm_sam_isaac" && !isSam && !isIsaac) {
        return { statusCode: 403, headers, body: JSON.stringify({ ok: false, error: "Unauthorized" }) };
      }

      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const { data } = await supabase
        .from("chat_messages")
        .select("*")
        .eq("room_id", roomId)
        .gte("created_at", cutoff)
        .order("created_at", { ascending: true })
        .limit(100);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, messages: data || [] }) };
    }

    if (action === "sendChatMessage") {
      const username = body.username || "";
      const roomId = body.roomId || "global";
      const n = username.toLowerCase().trim();
      const isSam = ["sam","samuel","samuel harms","sam harms","dr. pepper guy","dr pepper guy","coke guy"].includes(n);
      const isIsaac = ["isaac","isaac price"].includes(n);

      if (roomId === "dm_sam_isaac" && !isSam && !isIsaac) {
        return { statusCode: 403, headers, body: JSON.stringify({ ok: false, error: "Unauthorized" }) };
      }

      const message = (body.message || "").substring(0, 10000);

      // Server-side flag scanning for chatroom
      const flagPatterns = [
        { regex: /\b(nigger|nigg[ae]rs?|chink\b|gooks?\b|spick?\b|kike\b|wetback|paki\b|raghead|sand[\s-]?nigger)\b/i, type: "RACIAL_SLUR", severity: "HIGH" },
        { regex: /\b(shota|lolicon|shotacon|child[\s-]?porn|kiddie[\s-]?porn)\b/i, type: "MINOR_SEXUAL", severity: "CRITICAL" },
        { regex: /\b(rape\b|raping|rapist|incest\b|bestiality)\b/i, type: "SEVERE_SEXUAL", severity: "HIGH" },
      ];
      for (const rule of flagPatterns) {
        if (rule.regex.test(message)) {
          await supabase.from("flags").insert({
            username,
            flag_type: rule.type + " [CHATROOM:" + roomId + "]",
            severity: rule.severity,
            message: message.substring(0, 500),
          });
        }
      }

      const { data, error } = await supabase.from("chat_messages").insert({
        room_id: roomId,
        username,
        message,
      }).select().single();

      return { statusCode: 200, headers, body: JSON.stringify({ ok: !error, id: data?.id }) };
    }

    // ── Opus requests ──
    if (action === "requestOpus") {
      const { data } = await supabase.from("opus_requests").insert({
        username: body.username,
        reason: body.reason,
        status: "pending",
      }).select().single();
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, id: data?.id }) };
    }

    if (action === "checkOpusStatus") {
      const { data } = await supabase
        .from("opus_requests")
        .select("*")
        .eq("username", body.username)
        .eq("acknowledged", false)
        .neq("status", "pending")
        .order("created_at", { ascending: false })
        .limit(1);
      const pending = await supabase
        .from("opus_requests")
        .select("*")
        .eq("username", body.username)
        .eq("status", "pending")
        .eq("acknowledged", false)
        .limit(1);
      const request = (data && data[0]) || (pending.data && pending.data[0]) || null;
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, request }) };
    }

    if (action === "acknowledgeOpusResponse") {
      await supabase.from("opus_requests").update({ acknowledged: true }).eq("id", body.requestId);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    if (action === "getOpusRequests") {
      const { data } = await supabase
        .from("opus_requests")
        .select("*")
        .eq("status", "pending")
        .order("created_at", { ascending: false });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, requests: data || [] }) };
    }

    if (action === "respondOpus") {
      await supabase.from("opus_requests").update({
        status: body.approved ? "approved" : "denied",
        reply: body.reply || "",
      }).eq("id", body.requestId);
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    if (action === "authorizeOpus") {
      // Direct authorization — insert a pre-approved request
      await supabase.from("opus_requests").insert({
        username: body.username,
        reason: "Direct authorization by admin",
        status: "approved",
        reply: body.reply || "",
        acknowledged: false,
      });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Forums ──
    if (action === "getForumPosts") {
      const { data } = await supabase
        .from("forums")
        .select("*")
        .order("created_at", { ascending: false });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, posts: data || [] }) };
    }

    if (action === "submitForumPost") {
      const { error } = await supabase.from("forums").insert({
        username: body.username,
        title: body.title,
        language: body.language,
        description: body.description || "",
        code: (body.code || "").substring(0, 50000),
      });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: !error }) };
    }

    if (action === "deleteForumPost") {
      const n = (body.username || "").toLowerCase().trim();
      const isAdmin = ["istopx","jacob","jacob ulrich"].includes(n);
      const query = supabase.from("forums").delete().eq("id", body.postId);
      if (!isAdmin) query.eq("username", body.username);
      await query;
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    // ── Admin: save settings ──
    if (action === "saveSettings") {
      const master = await getConfig("master_passkey");
      if (body.masterPasskey !== master) {
        return { statusCode: 403, headers, body: JSON.stringify({ ok: false }) };
      }
      if (body.maxMsgs !== undefined) await supabase.from("config").upsert({ key: "max_msgs", value: String(body.maxMsgs) });
      if (body.modelLock !== undefined) await supabase.from("config").upsert({ key: "model_lock", value: body.modelLock });
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
    }

    if (action === "getSettings") {
      const maxMsgs = await getConfig("max_msgs") || "40";
      const modelLock = await getConfig("model_lock") || "";
      return { statusCode: 200, headers, body: JSON.stringify({ ok: true, maxMsgs, modelLock }) };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ ok: false, error: "Unknown action" }) };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ ok: false, error: err.message }) };
  }
};
