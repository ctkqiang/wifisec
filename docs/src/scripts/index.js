// ============================================================
// WifiSec 文档站交互脚本
// 职责：主题切换（持久化）、侧边导航滚动高亮、代码块复制、
// 移动端抽屉开关。全部原生 API，零依赖。
// ============================================================

(function () {
  'use strict';

  // ---------- 主题切换 ----------
  // 主题偏好存 localStorage；系统偏好仅作首次访问的初始值。
  var THEME_KEY = 'wifisec-docs-theme';
  var root = document.documentElement;
  var themeToggle = document.getElementById('themeToggle');

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* 隐私模式下写入被禁，静默跳过 */ }
  }

  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (e) { /* 同上 */ }
    if (saved === 'dark' || saved === 'light') {
      root.setAttribute('data-theme', saved);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      root.setAttribute('data-theme', 'dark');
    }
  })();

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    });
  }

  // ---------- 侧边导航滚动高亮 ----------
  // IntersectionObserver 观察 H2 所在 section，取视口最上方的活跃节，
  // 与侧边栏 href 一一对应；无 observer 支持时退化为不做高亮（可读性不受影响）。
  var navLinks = Array.prototype.slice.call(
    document.querySelectorAll('.sidebar nav a[href^="#"]')
  );
  var sections = navLinks
    .map(function (a) { return document.getElementById(a.getAttribute('href').slice(1)); })
    .filter(Boolean);

  function setActive(id) {
    navLinks.forEach(function (a) {
      a.classList.toggle('active', a.getAttribute('href') === '#' + id);
    });
  }

  if ('IntersectionObserver' in window && sections.length) {
    var visible = new Map(); // section -> 与视口顶部的距离

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        visible.set(en.target, en.isIntersecting ? en.boundingClientRect.top : Infinity);
      });
      var best = null;
      visible.forEach(function (top, sec) {
        // 活跃节 = 已越过视口顶部的节里最靠下的那个；都未越过时取第一个
        if (top <= 96 && (!best || top > visible.get(best))) best = sec;
      });
      if (!best) best = sections[0];
      setActive(best.id);
    }, { rootMargin: '-96px 0px -60% 0px', threshold: 0 });

    sections.forEach(function (s) { io.observe(s); });
  }

  // ---------- 代码块复制按钮 ----------
  // 为每个 pre 注入复制按钮；复制成功短暂变绿反馈。
  var COPY_ICON = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/></svg>';

  document.querySelectorAll('pre').forEach(function (pre) {
    var btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.type = 'button';
    btn.setAttribute('aria-label', '复制代码');
    btn.innerHTML = COPY_ICON;

    btn.addEventListener('click', function () {
      var text = pre.querySelector('code');
      var content = text ? text.innerText : pre.innerText;
      var done = function () {
        btn.classList.add('copied');
        setTimeout(function () { btn.classList.remove('copied'); }, 1200);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(content).then(done, function () { fallbackCopy(content, done); });
      } else {
        fallbackCopy(content, done);
      }
    });

    pre.appendChild(btn);
  });

  // execCommand 兜底：file:// 或旧浏览器下 clipboard API 可能不可用
  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* 复制失败不打断阅读 */ }
    document.body.removeChild(ta);
  }

  // ---------- 移动端抽屉 ----------
  var sidebar = document.getElementById('sidebar');
  var menuToggle = document.getElementById('menuToggle');

  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', function (e) {
      e.stopPropagation();
      sidebar.classList.toggle('open');
    });

    // 点正文任意处收起抽屉；导航跳转后也收起
    document.addEventListener('click', function (e) {
      if (sidebar.classList.contains('open') && !sidebar.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });

    navLinks.forEach(function (a) {
      a.addEventListener('click', function () { sidebar.classList.remove('open'); });
    });
  }
})();
