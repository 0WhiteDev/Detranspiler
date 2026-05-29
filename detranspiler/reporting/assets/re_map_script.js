(() => {
  const DATA = JSON.parse(document.getElementById("graph-data").textContent);
  const KIND_COLOR = { 
    entry: getComputedStyle(document.documentElement).getPropertyValue("--entry").trim() || "#f78166",
    java_export: "#79c0ff",
    java_method: getComputedStyle(document.documentElement).getPropertyValue("--java").trim() || "#3fb950",
    java_class: "#56d364",
    native_fn: getComputedStyle(document.documentElement).getPropertyValue("--native").trim() || "#d29922",
    jni_api: getComputedStyle(document.documentElement).getPropertyValue("--jni").trim() || "#a371f7",
  };
  const EDGE_COLOR = { 
    calls: "#6e7681",
    registers: "#3fb950",
    resolves: "#a371f7",
    jni_invoke: "#bc8cff",
    export_bridge: "#58a6ff",
    implements: "#56d364",
    declares: "#30363d",
    registrar: "#f0883e",
  };
  const KIND_LABEL = { 
    entry: "Entry point",
    java_export: "Java_* export",
    java_method: "Java method",
    java_class: "Java class",
    native_fn: "Native function",
    jni_api: "JNI API",
  };
  const canvas = document.getElementById("canvas");
  const ctx = canvas.getContext("2d");
  const searchInput = document.getElementById("search");
  const detail = document.getElementById("detail");
  const filtersEl = document.getElementById("filters");
  const edgeFiltersEl = document.getElementById("edgeFilters");
  const legendEl = document.getElementById("legend");

  const state = { 
    nodes: DATA.nodes.map((n, i) => ({ 
      ...n,
      x: (Math.random() - 0.5) * 600,
      y: (Math.random() - 0.5) * 400,
      vx: 0,
      vy: 0,
      r: n.kind === "entry" ? 14 : n.kind === "java_method" ? 11 : 9,
    } )),
    edges: DATA.edges.slice(),
    selectedId: null,
    hoverId: null,
    panX: 0,
    panY: 0,
    zoom: 1,
    dragging: false,
    dragNode: null,
    lastX: 0,
    lastY: 0,
    kindVisible: {} ,
    edgeVisible: {} ,
    search: "",
  };
  const kinds = [...new Set(state.nodes.map(n => n.kind))].sort();
  const edgeKinds = [...new Set(state.edges.map(e => e.kind))].sort();
  kinds.forEach(k => { state.kindVisible[k] = true; } );
  edgeKinds.forEach(k => { state.edgeVisible[k] = true; } );

  kinds.forEach(kind => { 
    const id = "kind-" + kind;
    const row = document.createElement("label");
    row.className = "chk";
    row.innerHTML = `<input type="checkbox" id="${id} " checked> ${ KIND_LABEL[kind] || kind} `;
    row.querySelector("input").addEventListener("change", (e) => { 
      state.kindVisible[kind] = e.target.checked;
      draw();
    } );
    filtersEl.appendChild(row);
    const leg = document.createElement("div");
    leg.className = "legend-row";
    leg.innerHTML = `<span class="dot" style="background:${KIND_COLOR[kind] || "#8b949e"} "></span>${ KIND_LABEL[kind] || kind} `;
    legendEl.appendChild(leg);
  } );

  edgeKinds.forEach(kind => { 
    const id = "edge-" + kind;
    const row = document.createElement("label");
    row.className = "chk";
    row.innerHTML = `<input type="checkbox" id="${id} " checked> ${kind} `;
    row.querySelector("input").addEventListener("change", (e) => { 
      state.edgeVisible[kind] = e.target.checked;
      draw();
    } );
    edgeFiltersEl.appendChild(row);
  } );

  function resize() { 
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = Math.floor(rect.width * devicePixelRatio);
    canvas.height = Math.floor(rect.height * devicePixelRatio);
    canvas.style.width = rect.width + "px";
    canvas.style.height = rect.height + "px";
    draw();
  } 

  function visibleNodes() { 
    const q = state.search.trim().toLowerCase();
    return state.nodes.filter(n => { 
      if (!state.kindVisible[n.kind]) return false;
      if (!q) return true;
      return n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q);
    } );
  } 

  function visibleNodeSet() { 
    return new Set(visibleNodes().map(n => n.id));
  } 

  function visibleEdges(nodeSet) { 
    return state.edges.filter(e => state.edgeVisible[e.kind] && nodeSet.has(e.source) && nodeSet.has(e.target));
  } 

  function nodeById(id) { 
    return state.nodes.find(n => n.id === id);
  } 

  function neighbors(id) { 
    const out = new Set();
    state.edges.forEach(e => { 
      if (e.source === id) out.add(e.target);
      if (e.target === id) out.add(e.source);
    } );
    return [...out];
  } 

  function metaText(meta) { 
    if (!meta || typeof meta !== "object") return "";
    const lines = [];
    for (const [k, v] of Object.entries(meta)) { 
      if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
      lines.push(k + ": " + (Array.isArray(v) ? v.join(", ") : String(v)));
    } 
    return lines.join("\n");
  } 

  function showDetail(node) { 
    if (!node) { 
      detail.innerHTML = '<div class="detail-meta">Click a node to inspect links, recovery metadata, and neighbors.</div>';
      return;
    } 
    const nbs = neighbors(node.id).map(id => nodeById(id)).filter(Boolean);
    const inbound = state.edges.filter(e => e.target === node.id).map(e => `${e.kind}  â ${ nodeById(e.source)?.label || e.source} `);
    const outbound = state.edges.filter(e => e.source === node.id).map(e => `${e.kind}  â ${ nodeById(e.target)?.label || e.target} `);
    detail.innerHTML = `
      <div class="detail-title">${escapeHtml(node.label)} </div>
      <div class="detail-kind">${escapeHtml(KIND_LABEL[node.kind] || node.kind)}  · ${escapeHtml(node.id)} </div>
      <div class="detail-meta">${escapeHtml(metaText(node.meta))} </div>
      <div class="detail-meta" style="margin-top:8px"><strong>In (${inbound.length} )</strong>\n${escapeHtml(inbound.slice(0,12).join("\n") || "â")} </div>
      <div class="detail-meta" style="margin-top:8px"><strong>Out (${outbound.length} )</strong>\n${escapeHtml(outbound.slice(0,12).join("\n") || "â")} </div>
      <div class="detail-meta" style="margin-top:8px"><strong>Neighbors (${nbs.length} )</strong>\n${escapeHtml(nbs.slice(0,12).map(n => n.label).join("\n") || "â")} </div>
    `;
  } 

  function escapeHtml(s) { 
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  } 

  function screenTransform() { 
    const w = canvas.width / devicePixelRatio;
    const h = canvas.height / devicePixelRatio;
    return { cx: w / 2 + state.panX, cy: h / 2 + state.panY, zoom: state.zoom };
  } 

  function toScreen(x, y) { 
    const t = screenTransform();
    return { x: t.cx + x * t.zoom, y: t.cy + y * t.zoom };
  } 

  function toWorld(sx, sy) { 
    const t = screenTransform();
    return { x: (sx - t.cx) / t.zoom, y: (sy - t.cy) / t.zoom };
  } 

  function pickNode(wx, wy) { 
    let best = null;
    let bestD = Infinity;
    visibleNodes().forEach(n => { 
      const d = Math.hypot(n.x - wx, n.y - wy);
      const hit = n.r + 4;
      if (d < hit && d < bestD) { best = n; bestD = d; } 
    } );
    return best;
  } 

  function simulate() { 
    const nodes = visibleNodes();
    const nodeSet = new Set(nodes.map(n => n.id));
    const edges = visibleEdges(nodeSet);
    const alpha = 0.35;
    for (let i = 0; i < nodes.length; i++) { 
      for (let j = i + 1; j < nodes.length; j++) { 
        const a = nodes[i], b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.hypot(dx, dy) || 0.01;
        const force = 900 / (dist * dist);
        dx = dx / dist * force;
        dy = dy / dist * force;
        a.vx -= dx; a.vy -= dy;
        b.vx += dx; b.vy += dy;
      } 
    } 
    edges.forEach(e => { 
      const a = nodeById(e.source), b = nodeById(e.target);
      if (!a || !b) return;
      let dx = b.x - a.x, dy = b.y - a.y;
      let dist = Math.hypot(dx, dy) || 0.01;
      const force = (dist - 120) * 0.02;
      dx = dx / dist * force; dy = dy / dist * force;
      a.vx += dx; a.vy += dy;
      b.vx -= dx; b.vy -= dy;
    } );
    nodes.forEach(n => { 
      n.vx -= n.x * 0.001;
      n.vy -= n.y * 0.001;
      if (state.selectedId === n.id || state.hoverId === n.id) return;
      n.vx *= 0.85; n.vy *= 0.85;
      n.x += n.vx * alpha;
      n.y += n.vy * alpha;
    } );
  } 

  function draw() { 
    const dpr = devicePixelRatio;
    const w = canvas.width / dpr;
    const h = canvas.height / dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const nodes = visibleNodes();
    const nodeSet = visibleNodeSet();
    const edges = visibleEdges(nodeSet);
    const highlight = new Set();
    if (state.selectedId) { 
      highlight.add(state.selectedId);
      neighbors(state.selectedId).forEach(id => highlight.add(id));
    } 

    ctx.lineWidth = 1;
    edges.forEach(e => { 
      const a = nodeById(e.source), b = nodeById(e.target);
      if (!a || !b) return;
      const p1 = toScreen(a.x, a.y), p2 = toScreen(b.x, b.y);
      const active = highlight.size && (highlight.has(a.id) || highlight.has(b.id));
      ctx.strokeStyle = active ? (EDGE_COLOR[e.kind] || "#8b949e") : (EDGE_COLOR[e.kind] || "#484f58");
      ctx.globalAlpha = active ? 0.95 : highlight.size ? 0.15 : 0.55;
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.stroke();
    } );
    ctx.globalAlpha = 1;

    nodes.forEach(n => { 
      const p = toScreen(n.x, n.y);
      const r = n.r * Math.max(0.7, state.zoom);
      const selected = state.selectedId === n.id;
      const hovered = state.hoverId === n.id;
      const dim = highlight.size && !highlight.has(n.id);
      ctx.globalAlpha = dim ? 0.25 : 1;
      ctx.beginPath();
      ctx.fillStyle = KIND_COLOR[n.kind] || "#8b949e";
      ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fill();
      if (selected || hovered) { 
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = selected ? 2.5 : 1.5;
        ctx.stroke();
      } 
      if (selected || hovered || n.kind === "entry" || n.kind === "java_method") { 
        ctx.fillStyle = "#e6edf3";
        ctx.font = "11px Segoe UI, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(n.label.length > 28 ? n.label.slice(0, 26) + "â¦" : n.label, p.x, p.y - r - 4);
      } 
      ctx.globalAlpha = 1;
    } );
  } 

  let tick = 0;
  function loop() { 
    if (tick < 240) simulate();
    draw();
    tick++;
    requestAnimationFrame(loop);
  } 

  function fitView() { 
    const nodes = visibleNodes();
    if (!nodes.length) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(n => { 
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    } );
    const w = canvas.width / devicePixelRatio;
    const h = canvas.height / devicePixelRatio;
    const spanX = maxX - minX || 1;
    const spanY = maxY - minY || 1;
    state.zoom = Math.min(w / (spanX + 120), h / (spanY + 120), 1.8);
    state.panX = -(minX + maxX) / 2 * state.zoom;
    state.panY = -(minY + maxY) / 2 * state.zoom;
    draw();
  } 

  function resetLayout() { 
    state.nodes.forEach(n => { 
      n.x = (Math.random() - 0.5) * 600;
      n.y = (Math.random() - 0.5) * 400;
      n.vx = 0; n.vy = 0;
    } );
    tick = 0;
  } 

  canvas.addEventListener("mousedown", (e) => { 
    const rect = canvas.getBoundingClientRect();
    const wx = toWorld(e.clientX - rect.left, e.clientY - rect.top).x;
    const wy = toWorld(e.clientX - rect.left, e.clientY - rect.top).y;
    const picked = pickNode(wx, wy);
    if (picked) {
      state.dragNode = picked;
      state.selectedId = picked.id;
      showDetail(picked);
    } else {
      state.dragging = true;
      state.lastX = e.clientX;
      state.lastY = e.clientY;
      canvas.classList.add("dragging");
    } 
    draw();
  } );

  window.addEventListener("mousemove", (e) => { 
    const rect = canvas.getBoundingClientRect();
    const wx = toWorld(e.clientX - rect.left, e.clientY - rect.top).x;
    const wy = toWorld(e.clientX - rect.left, e.clientY - rect.top).y;
    if (state.dragNode) { 
      state.dragNode.x = wx;
      state.dragNode.y = wy;
      state.dragNode.vx = 0;
      state.dragNode.vy = 0;
      draw();
      return;
    } 
    if (state.dragging) { 
      state.panX += e.clientX - state.lastX;
      state.panY += e.clientY - state.lastY;
      state.lastX = e.clientX;
      state.lastY = e.clientY;
      draw();
      return;
    } 
    const hover = pickNode(wx, wy);
    const next = hover ? hover.id : null;
    if (next !== state.hoverId) { 
      state.hoverId = next;
      draw();
    } 
  } );

  window.addEventListener("mouseup", () => { 
    state.dragging = false;
    state.dragNode = null;
    canvas.classList.remove("dragging");
  } );

  canvas.addEventListener("dblclick", (e) => { 
    const rect = canvas.getBoundingClientRect();
    const wx = toWorld(e.clientX - rect.left, e.clientY - rect.top).x;
    const wy = toWorld(e.clientX - rect.left, e.clientY - rect.top).y;
    const picked = pickNode(wx, wy);
    if (picked) {
      state.selectedId = picked.id;
      showDetail(picked);
      state.panX = -picked.x * state.zoom;
      state.panY = -picked.y * state.zoom;
      draw();
    } 
  } );

  canvas.addEventListener("wheel", (e) => { 
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left;
    const sy = e.clientY - rect.top;
    const before = toWorld(sx, sy);
    const factor = e.deltaY > 0 ? 0.92 : 1.08;
    state.zoom = Math.min(3, Math.max(0.2, state.zoom * factor));
    const after = toWorld(sx, sy);
    state.panX += (after.x - before.x) * state.zoom;
    state.panY += (after.y - before.y) * state.zoom;
    draw();
  }, { passive: false });

  searchInput.addEventListener("input", () => { 
    state.search = searchInput.value;
    draw();
  } );

  document.getElementById("fitBtn").addEventListener("click", fitView);
  document.getElementById("resetBtn").addEventListener("click", resetLayout);

  window.addEventListener("resize", resize);
  resize();
  fitView();
  loop();
} )();
