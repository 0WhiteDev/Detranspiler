(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const api = () => window.pywebview && window.pywebview.api;

  const state = {
    running: false,
    viewUrls: { report: null, map: null },
    outDir: "",
    pollTimer: null,
  };

  const fields = {
    inputDll: $("#inputDll"),
    outDir: $("#outDir"),
    mode: $("#mode"),
    force: $("#force"),
    useGhidra: $("#useGhidra"),
    ghidraDir: $("#ghidraDir"),
    pseudoC: $("#pseudoC"),
    functionsJson: $("#functionsJson"),
    useJar: $("#useJar"),
    decompileJar: $("#decompileJar"),
    jarPath: $("#jarPath"),
  };

  function waitForApi(maxMs) {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      (function tick() {
        if (api()) return resolve(api());
        if (Date.now() - start > maxMs) return reject(new Error("pywebview API unavailable"));
        setTimeout(tick, 50);
      })();
    });
  }

  function readForm() {
    return {
      input_dll: fields.inputDll.value.trim(),
      out_dir: fields.outDir.value.trim(),
      mode: fields.mode.value,
      force: fields.force.checked,
      use_ghidra: fields.useGhidra.checked,
      ghidra_install_dir: fields.ghidraDir.value.trim(),
      pseudo_c: fields.pseudoC.value.trim(),
      functions_json: fields.functionsJson.value.trim(),
      strings_json: "",
      use_jar: fields.useJar.checked,
      decompile_jar: fields.decompileJar.checked,
      jar_path: fields.jarPath.value.trim(),
    };
  }

  function writeForm(data) {
    if (!data) return;
    fields.inputDll.value = data.input_dll || "";
    fields.outDir.value = data.out_dir || "";
    fields.mode.value = data.mode || "AUTO";
    fields.force.checked = !!data.force;
    fields.useGhidra.checked = data.use_ghidra !== false;
    fields.ghidraDir.value = data.ghidra_install_dir || "";
    fields.pseudoC.value = data.pseudo_c || "";
    fields.functionsJson.value = data.functions_json || "";
    fields.useJar.checked = !!data.use_jar;
    fields.decompileJar.checked = data.decompile_jar !== false;
    fields.jarPath.value = data.jar_path || "";
    toggleJarFields();
    toggleGhidraFields();
  }

  function toggleJarFields() {
    const on = fields.useJar.checked;
    fields.jarPath.disabled = !on;
    fields.decompileJar.disabled = !on;
  }

  function toggleGhidraFields() {
    const on = fields.useGhidra.checked;
    fields.ghidraDir.disabled = !on;
  }

  const frameIds = {
    report: "frameReport",
    map: "frameMap",
  };

  function loadArtifactFrame(key) {
    const url = state.viewUrls[key];
    const frame = $("#" + frameIds[key]);
    if (!frame || !url) return;
    frame.classList.remove("hidden");
    if (frame.src !== url) {
      frame.src = url;
    }
  }

  function clearArtifactFrames() {
    state.viewUrls = { report: null, map: null };
    Object.values(frameIds).forEach((id) => {
      const frame = $("#" + id);
      if (frame) frame.src = "about:blank";
    });
    setArtifactNav({ report: null, map: null });
  }

  function setArtifactNav(urls) {
    state.viewUrls = urls || { report: null, map: null };
    const map = [
      ["report", "navReport", "tagReport", "frameReport", "emptyReport"],
      ["map", "navMap", "tagMap", "frameMap", "emptyMap"],
    ];
    map.forEach(([key, navId, tagId, frameId, emptyId]) => {
      const url = state.viewUrls[key];
      const nav = $("#" + navId);
      const tag = $("#" + tagId);
      const frame = $("#" + frameId);
      const empty = $("#" + emptyId);
      const available = !!url;
      nav.disabled = !available;
      tag.textContent = available ? "OK" : "-";
      if (available) {
        empty.classList.add("hidden");
        frame.classList.remove("hidden");
      } else {
        frame.src = "about:blank";
        frame.classList.add("hidden");
        empty.classList.remove("hidden");
      }
    });
    $("#btnOpenOut").disabled = !state.outDir;
  }

  async function setView(name) {
    if (name === "report" || name === "map") {
      if (api()) {
        const res = await api().ensure_view_urls();
        if (res.view_urls) {
          setArtifactNav(res.view_urls);
        }
      }
      loadArtifactFrame(name);
    }
    if (name === "sources") {
      await loadSourcesTree();
    }
    if (name === "nativemap") {
      await loadNativeMapTree();
    }
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === name);
    });
    document.querySelectorAll(".view").forEach((view) => {
      view.classList.toggle("active", view.id === "view" + capitalize(name));
    });
  }

  function capitalize(s) {
    if (s === "nativemap") return "Nativemap";
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function showSessionBanner(summary) {
    const el = $("#sessionBanner");
    if (!summary) {
      el.classList.remove("visible");
      return;
    }
    const rate = summary.recovery_rate;
    const recovered = summary.methods_with_body;
    const total = summary.methods_total;
    const rateLabel =
      rate != null && total != null
        ? `${rate}% recovery (${recovered != null ? recovered : "?"}/${total} native)`
        : "session loaded";
    el.innerHTML = `<strong>Session active</strong> - ${escapeHtml(summary.input_name || "binary")} · mode ${escapeHtml(summary.mode_resolved || summary.mode_requested || "?")} · ${escapeHtml(rateLabel)} · <code>${escapeHtml(summary.out_dir || "")}</code>`;
    el.classList.add("visible");
    $("#appMeta").textContent = summary.input_name ? `${summary.input_name} · ${rateLabel}` : "Session loaded";
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setCode(el, code, language) {
    if (window.CodeHighlight) {
      window.CodeHighlight.setHighlightedCode(el, code, language);
    } else if (el) {
      el.textContent = code || "";
    }
  }

  function setPlainCode(el, text) {
    if (window.CodeHighlight) {
      window.CodeHighlight.setPlainCode(el, text);
    } else if (el) {
      el.textContent = text || "";
    }
  }

  function appendConsole(lines) {
    const box = $("#console");
    box.innerHTML = (lines || [])
      .map((line) => {
        const cls = line.includes("ERROR") ? "line-err" : "line-info";
        return `<div class="${cls}">${escapeHtml(line)}</div>`;
      })
      .join("");
    box.scrollTop = box.scrollHeight;
  }

  function updateProgress(snap) {
    state.running = !!snap.running;
    const wrap = $("#progressWrap");
    wrap.style.display = state.running || (snap.logs && snap.logs.length) ? "block" : wrap.style.display;
    $("#progressFill").style.width = `${snap.percent || 0}%`;
    $("#progressPct").textContent = `${snap.percent || 0}%`;
    $("#progressLabel").textContent = snap.message || snap.phase || "…";
    appendConsole(snap.logs || []);
    $("#btnStart").disabled = state.running;
    $("#btnLoad").disabled = state.running;
    if (snap.error) {
      $("#progressLabel").textContent = snap.error;
    }
    if (snap.view_urls) {
      setArtifactNav(snap.view_urls);
    }
    if (snap.summary) {
      applySummary(snap.summary);
    }
  }

  function applySummary(summary) {
    state.outDir = summary.out_dir || fields.outDir.value.trim();
    showSessionBanner(summary);
    const urls = summary.view_urls || state.viewUrls;
    setArtifactNav(urls);
    const hasSources = !!(summary.artifacts && summary.artifacts.pseudocode_dir);
    $("#navSources").disabled = !state.outDir;
    $("#tagSources").textContent = state.outDir ? "…" : "-";
    const hasNativeMap = !!(summary.artifacts && summary.artifacts.native_map_dir);
    $("#navNativeMap").disabled = !hasNativeMap;
    $("#tagNativeMap").textContent = hasNativeMap ? "…" : "-";
    $("#btnOpenNativeMap").disabled = !hasNativeMap;
    if (hasNativeMap) {
      refreshNativeMapNav();
    }
  }

  async function loadSourcesTree() {
    if (!api()) return;
    const treeEl = $("#sourcesTree");
    const hint = $("#sourcesHint");
    treeEl.innerHTML = "";
    const data = await api().get_sources_tree();
    if (data.status !== "OK") {
      hint.textContent = data.error || "Sources unavailable.";
      $("#navSources").disabled = true;
      $("#tagSources").textContent = "-";
      return;
    }
    $("#navSources").disabled = false;
    $("#tagSources").textContent = String(data.entries_total || 0);
    hint.textContent = `${data.entries_total || 0} Java file(s) after decompile + detranspile`;
    const filter = ($("#sourcesSearch")?.value || "").trim().toLowerCase();
    for (const entry of data.entries || []) {
      if (filter && !entry.path.toLowerCase().includes(filter)) continue;
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.innerHTML = `<span>${escapeHtml(entry.path)}</span>`;
      btn.addEventListener("click", async () => {
        treeEl.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        await showSourceFile(entry.path);
      });
      li.appendChild(btn);
      treeEl.appendChild(li);
    }
  }

  async function showSourceFile(relPath) {
    const doc = await api().get_source_file(relPath);
    $("#sourcesPath").textContent = relPath;
    const code = doc.content || "";
    setCode($("#sourcesCode"), code, relPath.endsWith(".java") ? "java" : null);
  }

  async function refreshNativeMapNav() {
    if (!api()) return;
    const data = await api().get_native_map_tree();
    const available = data.status === "OK";
    $("#navNativeMap").disabled = !available;
    $("#btnOpenNativeMap").disabled = !available;
    $("#tagNativeMap").textContent = available ? String(data.methods_total || 0) : "-";
  }

  async function loadNativeMapTree() {
    if (!api()) return;
    const treeEl = $("#nativeMapTree");
    const hint = $("#nativeMapHint");
    treeEl.innerHTML = "";
    const data = await api().get_native_map_tree();
    if (data.status !== "OK") {
      hint.textContent = data.error || "Native map unavailable.";
      $("#navNativeMap").disabled = true;
      $("#tagNativeMap").textContent = "-";
      $("#btnOpenNativeMap").disabled = true;
      return;
    }
    $("#navNativeMap").disabled = false;
    $("#btnOpenNativeMap").disabled = false;
    $("#tagNativeMap").textContent = String(data.methods_total || 0);
    const binary = data.binary || "binary";
    const bodies = data.bodies_found != null ? `${data.bodies_found}/${data.methods_total}` : String(data.methods_total);
    hint.textContent = `${binary} · ${bodies} method(s) with decompiled C`;
    const filter = ($("#nativeMapSearch")?.value || "").trim().toLowerCase();

    for (const pkg of data.packages || []) {
      const pkgMethods = [];
      for (const cls of pkg.classes || []) {
        for (const m of cls.methods || []) {
          pkgMethods.push({ cls, m });
        }
      }
      if (!pkgMethods.length) continue;

      const visible = pkgMethods.filter(({ cls, m }) => {
        if (!filter) return true;
        const hay = [
          pkg.name,
          cls.name,
          m.method,
          m.java_signature,
          m.fn_symbol,
          m.address,
        ]
          .join(" ")
          .toLowerCase();
        return hay.includes(filter);
      });
      if (!visible.length) continue;

      const pkgBlock = document.createElement("div");
      pkgBlock.className = "nativemap-pkg";
      const pkgTitle = document.createElement("div");
      pkgTitle.className = "nativemap-pkg-title";
      pkgTitle.textContent = `package ${pkg.name}`;
      pkgBlock.appendChild(pkgTitle);

      const byClass = {};
      visible.forEach(({ cls, m }) => {
        byClass[cls.name] = byClass[cls.name] || { cls, methods: [] };
        byClass[cls.name].methods.push(m);
      });

      Object.keys(byClass)
        .sort()
        .forEach((clsName) => {
          const { cls, methods } = byClass[clsName];
          const clsBlock = document.createElement("div");
          clsBlock.className = "nativemap-class";
          const clsTitle = document.createElement("div");
          clsTitle.className = "nativemap-class-title";
          clsTitle.textContent = cls.name;
          clsBlock.appendChild(clsTitle);

          methods
            .sort((a, b) => String(a.method).localeCompare(String(b.method)))
            .forEach((m) => {
              const btn = document.createElement("button");
              btn.type = "button";
              btn.dataset.methodId = m.id;
              btn.innerHTML = `<span>${escapeHtml(m.java_signature || m.method)}</span><span class="fn">${escapeHtml(m.fn_symbol || "?")}${m.address ? " @ " + escapeHtml(m.address) : ""}</span>`;
              btn.addEventListener("click", async () => {
                treeEl.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
                btn.classList.add("active");
                await showNativeMapMethod(m.id);
              });
              clsBlock.appendChild(btn);
            });
          pkgBlock.appendChild(clsBlock);
        });

      treeEl.appendChild(pkgBlock);
    }
  }

  async function showNativeMapMethod(methodId) {
    const doc = await api().get_native_map_method(methodId);
    const meta = doc.method || {};
    const fqcn = meta.class_fqcn || meta.class_internal || "?";
    $("#nativeMapTitle").textContent = `${fqcn}.${meta.method || "?"}`;
    const chips = [];
    if (meta.java_signature) chips.push(`<span class="nativemap-chip"><strong>Java</strong> ${escapeHtml(meta.java_signature)}</span>`);
    if (meta.fn_symbol) chips.push(`<span class="nativemap-chip"><strong>DLL</strong> ${escapeHtml(meta.fn_symbol)}</span>`);
    if (meta.address) chips.push(`<span class="nativemap-chip"><strong>addr</strong> ${escapeHtml(meta.address)}</span>`);
    if (meta.calling_convention) chips.push(`<span class="nativemap-chip">${escapeHtml(meta.calling_convention)}</span>`);
    if (meta.decompiled_c_lines) {
      chips.push(`<span class="nativemap-chip"><strong>lines</strong> ${meta.decompiled_c_lines[0]}–${meta.decompiled_c_lines[1]}</span>`);
    }
    if (meta.confidence != null) chips.push(`<span class="nativemap-chip"><strong>conf</strong> ${meta.confidence}</span>`);
    if (meta.c_file) chips.push(`<span class="nativemap-chip">${escapeHtml(meta.c_file)}</span>`);
    if (meta.callees && meta.callees.length) {
      const shown = meta.callees.slice(0, 8).map((c) => escapeHtml(c)).join(", ");
      const more = meta.callees.length > 8 ? " …" : "";
      chips.push(`<span class="nativemap-chip"><strong>calls</strong> ${shown}${more}</span>`);
    }
    $("#nativeMapChips").innerHTML = chips.join("");
    if (doc.status !== "OK" || !doc.has_content) {
      setPlainCode(
        $("#nativeMapCode"),
        doc.error || "No decompiled C body found for this method in decompiled.c"
      );
      return;
    }
    setCode($("#nativeMapCode"), doc.content, "c");
  }

  async function pollProgress() {
    if (!api()) return;
    try {
      const snap = await api().get_progress();
      updateProgress(snap);
      const waitingForArtifacts =
        !snap.running && !snap.error && snap.percent >= 100 && !(snap.view_urls && snap.view_urls.report);
      if (snap.running || waitingForArtifacts) {
        state.pollTimer = setTimeout(pollProgress, waitingForArtifacts ? 200 : 400);
      } else if (!snap.error && snap.view_urls && snap.view_urls.report) {
        applySummary(snap.summary || { out_dir: state.outDir, view_urls: snap.view_urls });
        await setView("report");
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function init() {
    try {
      await waitForApi(8000);
    } catch (e) {
      $("#appMeta").textContent = "API error restart the app";
      return;
    }
    const theme = await api().get_theme_css();
    const themeEl = document.createElement("style");
    themeEl.textContent = theme;
    document.head.insertBefore(themeEl, document.head.firstChild);

    const version = await api().get_version();
    document.title = `Detranspiler v${version}`;
    const versionMeta = $("#appVersionMeta");
    if (versionMeta) versionMeta.textContent = `v${version}`;
    const settings = await api().get_settings();
    writeForm(settings);

    document.querySelectorAll(".nav-btn[data-view]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (btn.disabled) return;
        await setView(btn.dataset.view);
      });
    });

    document.querySelectorAll("[data-pick]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const kind = btn.dataset.pick;
        const picked = await api().pick_file(kind);
        if (!picked) return;
        if (kind === "dll") fields.inputDll.value = picked;
        else if (kind === "folder") fields.outDir.value = picked;
        else if (kind === "ghidra") fields.ghidraDir.value = picked;
        else if (kind === "jar") fields.jarPath.value = picked;
        else if (kind === "pseudo_c") fields.pseudoC.value = picked;
        else if (kind === "json") fields.functionsJson.value = picked;
      });
    });

    fields.useJar.addEventListener("change", toggleJarFields);
    fields.useGhidra.addEventListener("change", toggleGhidraFields);

    $("#btnStart").addEventListener("click", async () => {
      const config = readForm();
      await api().save_settings(config);
      clearArtifactFrames();
      setView("setup");
      $("#progressWrap").style.display = "block";
      appendConsole(["Starting analysis…"]);
      const res = await api().start_analysis(config);
      if (!res.ok) {
        appendConsole([`ERROR: ${res.error}`]);
        return;
      }
      if (res.view_urls) {
        setArtifactNav(res.view_urls);
      }
      pollProgress();
    });

    $("#btnLoad").addEventListener("click", async () => {
      const out = fields.outDir.value.trim();
      if (!out) {
        appendConsole(["ERROR: Set output directory first"]);
        $("#progressWrap").style.display = "block";
        return;
      }
      $("#progressWrap").style.display = "block";
      appendConsole([`Loading session from ${out}…`]);
      const res = await api().load_session(out);
      if (!res.ok) {
        appendConsole([`ERROR: ${res.error}`]);
        return;
      }
      applySummary(res.summary);
      appendConsole(["Session loaded."]);
      await setView("report");
    });

    $("#btnOpenOut").addEventListener("click", async () => {
      if (state.outDir) await api().reveal_in_explorer(state.outDir);
    });

    $("#btnDoctor").addEventListener("click", async () => {
      const diag = await api().run_doctor();
      renderDoctor(diag);
    });

    $("#sourcesSearch")?.addEventListener("input", () => {
      if ($("#viewSources").classList.contains("active")) loadSourcesTree();
    });

    $("#nativeMapSearch")?.addEventListener("input", () => {
      if ($("#viewNativemap").classList.contains("active")) loadNativeMapTree();
    });

    $("#btnOpenNativeMap")?.addEventListener("click", async () => {
      if (api()) await api().open_native_map_folder();
    });


    const out = fields.outDir.value.trim();
    if (out) {

    }
  }

  function renderDoctor(diag) {
    const grid = $("#doctorGrid");
    const cards = [];
    const py = diag.python || {};
    cards.push(card("Python", py.ok ? "OK" : "Issue", `${py.version || "?"}`, py.ok));
    Object.entries(diag.deps || {}).forEach(([name, info]) => {
      cards.push(card(name, info.status || "?", info.version || "", info.status === "OK"));
    });
    const java = diag.java || {};
    cards.push(card("Java", java.status || "?", (java.output || java.error || "").split("\n")[0] || "", java.status === "OK"));
    const gh = diag.ghidra || {};
    cards.push(card("Ghidra", gh.status || "?", gh.install_dir || gh.error || "", gh.status === "OK"));
    grid.innerHTML = cards.join("");
  }

  function card(title, status, detail, ok) {
    return `<div class="doctor-card ${ok ? "ok" : "bad"}"><strong>${escapeHtml(title)}: ${escapeHtml(status)}</strong><div class="muted">${escapeHtml(detail || "")}</div></div>`;
  }

  window.addEventListener("pywebviewready", init);
  if (window.pywebview) init();
})();
