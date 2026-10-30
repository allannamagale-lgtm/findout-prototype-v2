/* ============================================================
   FINDOUT — Client JS
   Handles: theme toggle, mobile nav, toasts, notif polling,
   highlight-scroll, form submit states.
   ============================================================ */
(function () {
  'use strict';

  // -------- Theme toggle --------
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      const cur = document.documentElement.getAttribute('data-theme');
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('findout-theme', next);
    });
  }

  // -------- Hamburger --------
  const hamburger = document.getElementById('hamburger');
  const navMain = document.getElementById('nav-main');
  if (hamburger && navMain) {
    hamburger.addEventListener('click', function () {
      const open = navMain.classList.toggle('open');
      hamburger.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // -------- Toasts --------
  function dismissToast(t) {
    if (!t || t.classList.contains('hiding')) return;
    t.classList.add('hiding');
    setTimeout(function () { t.remove(); }, 250);
  }

  document.querySelectorAll('.toast').forEach(function (t) {
    const btn = t.querySelector('.toast-close');
    if (btn) btn.addEventListener('click', function () { dismissToast(t); });
    setTimeout(function () { dismissToast(t); }, 5000);
  });

  // -------- Highlight & scroll to claim --------
  (function () {
    var params = new URLSearchParams(window.location.search);
    var id = params.get('highlight_claim');
    if (!id) return;
    var el = document.getElementById('claim-' + id);
    if (!el) return;
    setTimeout(function () {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('highlight');
      setTimeout(function () { el.classList.remove('highlight'); }, 3000);
    }, 100);
  })();

  // -------- Notification polling --------
  var notifBell = document.querySelector('.notif-bell');
  if (notifBell && notifBell.dataset.authenticated !== '0') {
    var pollUrl = '/notifications/count';
    function poll() {
      fetch(pollUrl, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) return;
          var badge = document.getElementById('notif-badge');
          if (!badge) {
            if (data.count > 0) {
              badge = document.createElement('span');
              badge.className = 'notif-badge';
              badge.id = 'notif-badge';
              badge.textContent = data.count;
              notifBell.appendChild(badge);
            }
          } else {
            if (data.count > 0) {
              badge.textContent = data.count;
              badge.style.display = 'flex';
            } else {
              badge.style.display = 'none';
            }
          }
        })
        .catch(function () { /* silent */ });
      setTimeout(poll, 15000);
    }
    poll();
  }

  // -------- Form submit states (prevent double-submit) --------
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var btns = form.querySelectorAll('button[type="submit"]');
      btns.forEach(function (b) {
        b.disabled = true;
        b.dataset.originalText = b.textContent;
        b.textContent = 'Please wait…';
      });
      // Safety: re-enable after 10s in case of navigation issues
      setTimeout(function () {
        btns.forEach(function (b) {
          b.disabled = false;
          if (b.dataset.originalText) b.textContent = b.dataset.originalText;
        });
      }, 10000);
    });
  });

  // -------- Cookie / POPI Banner --------
  var cookieBanner = document.getElementById('cookie-banner');
  if (cookieBanner) {
    if (!localStorage.getItem('findout-cookie-consent')) {
      cookieBanner.style.display = 'flex';
    }
    var acceptBtn = document.getElementById('accept-cookies');
    if (acceptBtn) {
      acceptBtn.addEventListener('click', function () {
        localStorage.setItem('findout-cookie-consent', 'true');
        cookieBanner.style.display = 'none';
      });
    }
  }

  // -------- Button Loading Spinner --------
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var btns = form.querySelectorAll('button[type="submit"]');
      btns.forEach(function (b) {
        b.disabled = true;
        b.classList.add('btn-spinner');
        b.dataset.originalText = b.textContent;
        b.textContent = ''; // Spinner will append
      });
      setTimeout(function () {
        btns.forEach(function (b) {
          b.disabled = false;
          b.classList.remove('btn-spinner');
          if (b.dataset.originalText) b.textContent = b.dataset.originalText;
        });
      }, 10000);
    });
  });

  // -------- Service worker (PWA) --------
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/static/sw.js').catch(function () { /* silent */ });
    });
  }
})();