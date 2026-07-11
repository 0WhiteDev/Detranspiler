(function (global) {
  "use strict";

  const PLACEHOLDER = (i) => `\uE000HL${i}\uE001`;

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function wrap(cls, text) {
    return `<span class="${cls}">${text}</span>`;
  }

  function protect(text, re, cls, store) {
    return text.replace(re, (match) => {
      store.push(wrap(cls, match));
      return PLACEHOLDER(store.length - 1);
    });
  }

  function protectFn(text, re, fn, store) {
    return text.replace(re, (...args) => {
      const match = args[0];
      store.push(fn(match, ...args.slice(1)));
      return PLACEHOLDER(store.length - 1);
    });
  }

  function protectWords(text, words, cls, store) {
    if (!words.length) return text;
    const re = new RegExp(`\\b(${words.join("|")})\\b`, "g");
    return text.replace(re, (match) => {
      store.push(wrap(cls, match));
      return PLACEHOLDER(store.length - 1);
    });
  }

  function restore(text, store) {
    return text.replace(/\uE000HL(\d+)\uE001/g, (_, idx) => store[Number(idx)] || "");
  }

  const JAVA_KW = [
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const",
    "continue", "default", "do", "double", "else", "enum", "extends", "final", "finally", "float",
    "for", "goto", "if", "implements", "import", "instanceof", "int", "interface", "long", "new",
    "non-sealed", "package", "permits", "private", "protected", "public", "record", "return",
    "sealed", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw",
    "throws", "transient", "try", "void", "volatile", "while", "yield", "true", "false", "null",
  ].sort((a, b) => b.length - a.length);

  const JAVA_TYPES = [
    "String", "Object", "Class", "Integer", "Long", "Double", "Float", "Boolean", "Byte", "Short",
    "Character", "Void", "List", "Map", "Set", "Optional", "Record",
  ];

  const C_KW = [
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "NULL", "true", "false",
  ].sort((a, b) => b.length - a.length);

  const C_TYPES = [
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8", "longlong", "ulonglong",
    "byte", "ushort", "uint", "size_t", "code", "pointer", "bool", "wchar_t",
  ];

  function protectLiterals(s, store) {
    s = protect(s, /\/\*[\s\S]*?\*\//g, "hl-com", store);
    s = protect(s, /\/\/[^\n]*/g, "hl-com", store);
    s = protect(s, /"(?:\\.|[^"\\])*"/g, "hl-str", store);
    s = protect(s, /'(?:\\.|[^'\\])*'/g, "hl-str", store);
    return s;
  }

  function highlightJava(code) {
    const store = [];
    let s = escapeHtml(code);
    s = protectLiterals(s, store);
    s = protect(s, /@[A-Za-z_][\w.]*/g, "hl-ann", store);
    s = protect(s, /\bnative\b/g, "hl-native", store);
    s = protectWords(s, JAVA_TYPES, "hl-type", store);
    s = protectWords(s, JAVA_KW, "hl-kw", store);
    return restore(s, store);
  }

  function highlightC(code) {
    const store = [];
    let s = escapeHtml(code);
    s = protectLiterals(s, store);
    s = protectFn(
      s,
      /\(\*\*\(code \*\*\)\(\*[^+]+\+\s*(0x[0-9a-fA-F]+)\)\)/g,
      (match, off) => match.replace(off, wrap("hl-jni", off)),
      store
    );
    s = protect(s, /#\s*(?:include|define|ifdef|ifndef|endif|pragma|if|else|elif)[^\n]*/g, "hl-pre", store);
    s = protect(s, /\b(FUN_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+)\b/g, "hl-fn", store);
    s = protect(s, /\b(DAT_[0-9A-Fa-f]+)\b/g, "hl-glbl", store);
    s = protect(s, /\b(param_\d+|local_[\w$]+|uVar\d+|lVar\d+|iVar\d+|cVar\d+|puVar\d+)\b/g, "hl-var", store);
    s = protect(s, /\b0x[0-9a-fA-F]+\b/g, "hl-num", store);
    s = protect(s, /\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g, "hl-num", store);
    s = protectWords(s, C_TYPES, "hl-type", store);
    s = protectWords(s, C_KW, "hl-kw", store);
    return restore(s, store);
  }

  function setHighlightedCode(container, code, language) {
    if (!container) return;
    let codeEl = container.querySelector("code");
    if (!codeEl) {
      container.textContent = "";
      codeEl = document.createElement("code");
      container.appendChild(codeEl);
    }
    if (!code) {
      codeEl.className = "";
      codeEl.textContent = "";
      return;
    }
    const lang = (language || "").toLowerCase();
    codeEl.className = lang ? `hl-lang-${lang}` : "";
    if (lang === "java") {
      codeEl.innerHTML = highlightJava(code);
    } else if (lang === "c" || lang === "cpp") {
      codeEl.innerHTML = highlightC(code);
    } else {
      codeEl.textContent = code;
    }
  }

  function setPlainCode(container, text) {
    if (!container) return;
    let codeEl = container.querySelector("code");
    if (!codeEl) {
      container.textContent = "";
      codeEl = document.createElement("code");
      container.appendChild(codeEl);
    }
    codeEl.className = "";
    codeEl.textContent = text || "";
  }

  function setInteractiveCode(container, code, language, ranges, onSelect, firstLine, fallbackRange) {
    if (!container) return;
    container.textContent = "";
    const codeEl = document.createElement("code");
    codeEl.className = "source-lines hl-lang-" + (language || "").toLowerCase();
    const normalized = String(code || "").replace(/\r\n?/g, "\n");
    const lines = normalized.endsWith("\n") ? normalized.slice(0, -1).split("\n") : normalized.split("\n");
    const orderedRanges = Array.isArray(ranges) ? [...ranges].sort((a, b) => Number(a.start_line || 0) - Number(b.start_line || 0)) : [];
    const initialLine = Number(firstLine) || 1;
    let rangeIndex = 0;
    for (let index = 0; index < lines.length; index += 1) {
      const lineNumber = initialLine + index;
      while (rangeIndex + 1 < orderedRanges.length && lineNumber > Number(orderedRanges[rangeIndex].end_line || 0)) {
        rangeIndex += 1;
      }
      const candidate = orderedRanges[rangeIndex] || {};
      const range = Number(candidate.start_line || 0) <= lineNumber && lineNumber <= Number(candidate.end_line || 0) ? candidate : fallbackRange || {};
      const row = document.createElement("span");
      const interactive = typeof onSelect === "function";
      row.className = "source-line provenance-" + (range.tone || "unknown") + (interactive ? " source-line-action" : "");
      row.dataset.line = String(lineNumber);
      if (interactive) {
        row.tabIndex = 0;
        row.setAttribute("role", "button");
      }
      row.title = range.label || "Unknown source";
      const number = document.createElement("span");
      number.className = "source-line-number";
      number.textContent = String(lineNumber);
      const marker = document.createElement("span");
      marker.className = "source-line-marker";
      const content = document.createElement("span");
      content.className = "source-line-text";
      const value = lines[index] || " ";
      if ((language || "").toLowerCase() === "java") {
        content.innerHTML = highlightJava(value);
      } else if ((language || "").toLowerCase() === "c") {
        content.innerHTML = highlightC(value);
      } else {
        content.textContent = value;
      }
      if (interactive) {
        const select = () => {
          codeEl.querySelectorAll(".source-line.selected").forEach((item) => item.classList.remove("selected"));
          row.classList.add("selected");
          onSelect(lineNumber);
        };
        row.addEventListener("click", select);
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            select();
          }
        });
      }
      row.append(number, marker, content);
      codeEl.appendChild(row);
    }
    container.appendChild(codeEl);
  }

  global.CodeHighlight = {
    escapeHtml,
    highlightJava,
    highlightC,
    setHighlightedCode,
    setInteractiveCode,
    setPlainCode,
  };
})(window);
