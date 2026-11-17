/* مصروفي — تطبيق مصروف شخصي يعمل بالكامل داخل المتصفح.
 * الأمان:
 *  - كل البيانات مشفّرة بـ AES-GCM 256 بمفتاح مشتق من اسم المستخدم وكلمة المرور (PBKDF2-SHA256، 600,000 دورة).
 *  - لا شيء يُرسل لأي خادم: لا fetch ولا مكتبات خارجية ولا خطوط خارجية.
 *  - الواجهة تُبنى بـ textContent فقط (لا innerHTML) لمنع حقن السكربتات.
 *  - قفل تلقائي بعد مدة خمول، وتأخير متزايد بعد محاولات الدخول الخاطئة.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------- ثوابت
  var VAULT_KEY = 'masroufi.vault.v2';
  var GUARD_KEY = 'masroufi.guard.v1';
  // بيانات الدخول الافتراضية — تُستخدم مرة واحدة فقط، ويُجبر المستخدم على تغييرها في أول دخول
  var DEFAULT_USER = 'masroufi';
  var DEFAULT_PASS = 'Masroufi@2026';
  var USER_RE = /^[a-z0-9._-]{3,32}$/;
  var KDF_ITER = 600000;
  var MAX_AMOUNT = 10000000;
  var MAX_TEXT = 120;
  var MAX_CSV_BYTES = 2 * 1024 * 1024;
  var MAX_CSV_ROWS = 3000;
  var MAX_BACKUP_BYTES = 5 * 1024 * 1024;
  var MONTHS = ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر'];
  var CATS = ['الطعام والمطاعم', 'السكن', 'التسوق', 'السيارة والوقود', 'فواتير واشتراكات', 'الصحة', 'التعليم', 'الاستراحة', 'أخرى'];
  var CAT_WORDS = [
    ['الطعام والمطاعم', ['مطعم', 'مطاعم', 'كافيه', 'قهوة', 'بقالة', 'هنقرستيشن', 'جاهز', 'مرسول', 'كيتا', 'تمرة', 'restaurant', 'cafe', 'coffee', 'hungerstation', 'jahez', 'mrsool', 'keeta', 'tamimi', 'panda', 'othaim', 'danube', 'starbucks', 'mcdonald', 'kfc', 'albaik']],
    ['السيارة والوقود', ['وقود', 'محطة', 'بنزين', 'ساسكو', 'نفط', 'الدريس', 'غسيل', 'fuel', 'petrol', 'sasco', 'aldrees', 'naft', 'car']],
    ['فواتير واشتراكات', ['فاتورة', 'سداد', 'كهرباء', 'مياه', 'اتصالات', 'موبايلي', 'زين', 'stc', 'mobily', 'zain', 'netflix', 'shahid', 'spotify', 'apple', 'google', 'icloud', 'sadad']],
    ['التسوق', ['امازون', 'أمازون', 'نون', 'شي ان', 'متجر', 'جرير', 'ايكيا', 'amazon', 'noon', 'shein', 'jarir', 'ikea', 'extra', 'store', 'shop']],
    ['الصحة', ['صيدلية', 'مستشفى', 'عيادة', 'النهدي', 'الدواء', 'pharmacy', 'nahdi', 'hospital', 'clinic']],
    ['السكن', ['ايجار', 'إيجار', 'rent', 'ejar']]
  ];

  // ---------------------------------------------------------------- أدوات عامة
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function $(id) { return document.getElementById(id); }

  function el(tag, props) {
    var e = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = String(v);
        else if (k === 'css') Object.keys(v).forEach(function (p) { e.style.setProperty(p, v[p]); });
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') e.addEventListener(k.slice(2), v);
        else if (k === 'value') e.value = v;
        else e.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) append(e, arguments[i]);
    return e;
  }
  function append(e, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { append(e, x); }); return; }
    e.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }

  function uid() {
    var a = new Uint8Array(9); crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }
  function b64(buf) {
    var s = ''; var a = new Uint8Array(buf);
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function unb64(s) {
    var bin = atob(s); var a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  // تحويل الأرقام العربية/الفارسية إلى لاتينية
  function latinDigits(s) {
    return String(s).replace(/[٠-٩]/g, function (d) { return String(d.charCodeAt(0) - 0x0660); })
      .replace(/[۰-۹]/g, function (d) { return String(d.charCodeAt(0) - 0x06F0); });
  }
  // تنظيف النص: حذف محارف التحكم ومحارف قلب الاتجاه (تُستخدم في خداع العرض)
  function cleanText(s, max) {
    return String(s == null ? '' : s)
      .replace(/[\u0000-\u001F\u007F‎‏‪-‮⁦-⁩]/g, ' ')
      .replace(/\s+/g, ' ').trim().slice(0, max || MAX_TEXT);
  }
  function parseAmount(s, allowZero) {
    var t = latinDigits(s).replace(/[\s,٬]/g, '').replace('٫', '.');
    if (!/^\d+(\.\d{1,2})?$/.test(t)) return null;
    var n = Number(t);
    if (!isFinite(n) || n > MAX_AMOUNT) return null;
    if (n === 0 && !allowZero) return null;
    return Math.round(n * 100) / 100;
  }
  function validDate(s) {
    if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
    var y = +s.slice(0, 4), m = +s.slice(5, 7), d = +s.slice(8, 10);
    if (y < 2000 || y > 2100 || m < 1 || m > 12) return false;
    return d >= 1 && d <= new Date(y, m, 0).getDate();
  }
  function today() {
    var d = new Date();
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }
  function mkey(date) { return date.slice(0, 7); }
  function monthName(k) { return MONTHS[+k.slice(5, 7) - 1] + ' ' + k.slice(0, 4); }
  function monthShort(k) { return MONTHS[+k.slice(5, 7) - 1]; }
  function addMonths(k, n) {
    var y = +k.slice(0, 4), m = +k.slice(5, 7) - 1 + n;
    y += Math.floor(m / 12); m = ((m % 12) + 12) % 12;
    return y + '-' + String(m + 1).padStart(2, '0');
  }
  function fmt(n) { return Math.round(n).toLocaleString('en-US'); }
  function dShort(d) { return d.slice(8, 10) + '/' + d.slice(5, 7); }
  function sum(arr, f) { return arr.reduce(function (a, x) { return a + (f ? f(x) : x); }, 0); }

  // ---------------------------------------------------------------- نموذج البيانات + التحقق
  function emptyState() {
    return { v: 1, setup: false, demo: false, profile: { name: '', balance: 0, lockMinutes: 5 },
      sources: [], incomes: [], expenses: [], debts: [], entities: [] };
  }
  // يعيد بناء الحالة من حقول معروفة فقط، ويرفض أي قيمة غير صالحة (يحمي من ملفات نسخ احتياطي معدّلة)
  function normalize(raw) {
    var s = emptyState();
    if (!raw || typeof raw !== 'object') return s;
    var amt = function (x, z) { return typeof x === 'number' && isFinite(x) && x >= 0 && x <= MAX_AMOUNT && (z || x > 0) ? Math.round(x * 100) / 100 : null; };
    var arr = function (x, lim) { return Array.isArray(x) ? x.slice(0, lim || 20000) : []; };
    var id = function (x) { return typeof x === 'string' && /^[a-f0-9]{6,32}$/.test(x) ? x : uid(); };
    var txt = function (x) { return cleanText(x); };
    var mk = function (x) { return typeof x === 'string' && /^\d{4}-\d{2}$/.test(x) ? x : mkey(today()); };
    s.demo = raw.demo === true;
    s.setup = raw.setup === true;
    var p = raw.profile || {};
    s.profile.name = cleanText(p.name, 60);
    s.profile.balance = amt(p.balance, true) || 0;
    s.profile.lockMinutes = [1, 2, 5, 10, 15, 30].indexOf(p.lockMinutes) >= 0 ? p.lockMinutes : 5;
    arr(raw.sources, 200).forEach(function (x) {
      var a = amt(x && x.amount); if (!a || !txt(x.name)) return;
      var day = Number.isInteger(x.day) && x.day >= 1 && x.day <= 31 ? x.day : 0;
      s.sources.push({ id: id(x.id), name: txt(x.name), kind: txt(x.kind) || 'راتب شهري', amount: a, day: day, since: mk(x.since) });
    });
    arr(raw.incomes).forEach(function (x) {
      var a = amt(x && x.amount); if (!a || !validDate(x.date)) return;
      s.incomes.push({ id: id(x.id), date: x.date, source: txt(x.source) || 'إيراد آخر', amount: a, note: txt(x.note) });
    });
    arr(raw.expenses).forEach(function (x) {
      var a = amt(x && x.amount); if (!a || !validDate(x.date)) return;
      s.expenses.push({ id: id(x.id), date: x.date, desc: txt(x.desc) || 'بدون وصف', cat: CATS.indexOf(x.cat) >= 0 ? x.cat : 'أخرى', amount: a });
    });
    arr(raw.debts, 500).forEach(function (x) {
      var t = amt(x && x.total); if (!t || !txt(x.name)) return;
      var d = { id: id(x.id), name: txt(x.name), dir: x.dir === 'for' ? 'for' : 'on', total: t,
        paid: Math.min(t, amt(x.paid, true) || 0), monthly: amt(x.monthly, true) || 0,
        end: cleanText(x.end, 12), payments: [] };
      arr(x.payments, 2000).forEach(function (y) {
        var a = amt(y && y.amount); if (!a || !validDate(y.date)) return;
        d.payments.push({ id: id(y.id), date: y.date, amount: a });
      });
      s.debts.push(d);
    });
    arr(raw.entities, 500).forEach(function (x) {
      if (!x || !txt(x.name)) return;
      var e = { id: id(x.id), type: x.type === 'a' ? 'a' : 'c', name: txt(x.name), closed: x.closed === true,
        deadline: validDate(x.deadline) ? x.deadline : '', moves: [] };
      arr(x.moves, 5000).forEach(function (y) {
        var a = amt(y && y.amount); if (!a || !validDate(y.date)) return;
        e.moves.push({ id: id(y.id), date: y.date, dir: y.dir === 'out' ? 'out' : 'in', amount: a, desc: txt(y.desc) });
      });
      s.entities.push(e);
    });
    return s;
  }

  function demoState() {
    var s = emptyState(); s.demo = true;
    var cur = mkey(today());
    s.profile.balance = 15000;
    s.sources = [
      { id: uid(), name: 'جهة العمل الأساسية', kind: 'راتب شهري', amount: 9000, day: 27, since: addMonths(cur, -12) },
      { id: uid(), name: 'عمل جزئي', kind: 'راتب شهري', amount: 4000, day: 27, since: addMonths(cur, -12) },
      { id: uid(), name: 'مكافأة شهرية', kind: 'مكافأة', amount: 1500, day: 1, since: addMonths(cur, -12) }
    ];
    var spend = [
      ['الطعام والمطاعم', 1640, ['مطعم — شراء بالبطاقة', 'بقالة الحي', 'طلب توصيل']],
      ['السكن', 1833, ['تحويل لحساب الإيجار']],
      ['التسوق', 1350, ['متجر إلكتروني', 'ملابس']],
      ['السيارة والوقود', 950, ['محطة وقود', 'غسيل سيارة']],
      ['فواتير واشتراكات', 430, ['فاتورة جوال', 'اشتراك إنترنت']],
      ['الاستراحة', 250, ['قطة الاستراحة']],
      ['أخرى', 760, ['هدية', 'مصاريف متفرقة']]
    ];
    var wobble = [0.95, 0.9, 1.15, 1.05, 0.88, 0.97, 1.12, 0.93, 0.99, 1.0, 1.08];
    for (var i = 10; i >= 0; i--) {
      var k = addMonths(cur, -i);
      var w = wobble[10 - i];
      spend.forEach(function (c, j) {
        var f = (i === 0 && j === 0) ? 1.28 : (i === 0 && j === 2) ? 1.19 : w;
        var amount = Math.round(c[1] * f);
        var parts = c[2].length;
        c[2].forEach(function (desc, n) {
          var day = Math.min(27, 3 + n * 9 + j);
          s.expenses.push({ id: uid(), date: k + '-' + String(day).padStart(2, '0'), desc: desc, cat: c[0], amount: Math.round(amount / parts) });
        });
      });
    }
    s.incomes.push({ id: uid(), date: cur + '-05', source: 'إيراد آخر', amount: 1200, note: 'مكافأة تقديم دورة' });
    s.debts = [
      { id: uid(), name: 'تمويل شخصي', dir: 'on', total: 120000, paid: 54000, monthly: 1500, end: '2030', payments: [] },
      { id: uid(), name: 'تمويل سيارة', dir: 'on', total: 85000, paid: 61000, monthly: 1700, end: '2028', payments: [] },
      { id: uid(), name: 'سلفة شخصية', dir: 'on', total: 10000, paid: 6000, monthly: 500, end: '2027', payments: [] },
      { id: uid(), name: 'بطاقة ائتمانية', dir: 'on', total: 8000, paid: 8000, monthly: 0, end: '', payments: [] },
      { id: uid(), name: 'سلفة لصديق', dir: 'for', total: 3000, paid: 0, monthly: 0, end: '', payments: [] }
    ];
    var prev = addMonths(cur, -1);
    s.entities = [
      { id: uid(), type: 'c', name: 'جمعية خيرية (عهدة)', closed: false, deadline: '', moves: [
        { id: uid(), date: prev + '-02', dir: 'in', amount: 5000, desc: 'استلام عهدة' },
        { id: uid(), date: prev + '-14', dir: 'out', amount: 3850, desc: 'مستلزمات أنشطة' }] },
      { id: uid(), type: 'c', name: 'مشروع عمل (عهدة)', closed: false, deadline: '', moves: [
        { id: uid(), date: prev + '-03', dir: 'in', amount: 2500, desc: 'استلام عهدة' },
        { id: uid(), date: prev + '-11', dir: 'out', amount: 900, desc: 'اشتراك استضافة' }] },
      { id: uid(), type: 'a', name: 'أمانة المسجد', closed: false, deadline: '', moves: [
        { id: uid(), date: prev + '-02', dir: 'in', amount: 6000, desc: 'من متبرع لكتب المسجد' },
        { id: uid(), date: prev + '-20', dir: 'out', amount: 1800, desc: 'شراء مصاحف' }] },
      { id: uid(), type: 'a', name: 'أمانة جمعية', closed: false, deadline: '', moves: [
        { id: uid(), date: prev + '-18', dir: 'in', amount: 2500, desc: 'مبلغ محفوظ لصالح الجمعية' }] }
    ];
    return s;
  }

  // ---------------------------------------------------------------- الخزنة المشفّرة
  var session = { key: null, salt: null, state: null, user: null };

  function storageGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function storageSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  function storageDel(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }

  function cryptoReady() { return !!(window.crypto && crypto.subtle && window.isSecureContext !== false); }

  function normUser(u) { return latinDigits(String(u || '')).trim().toLowerCase(); }
  // المفتاح مشتق من اسم المستخدم وكلمة المرور معًا، فأي خطأ في أحدهما يفشل فك التشفير بنفس الرسالة
  function deriveKey(user, pass, salt, iter) {
    var material = normUser(user) + '\u0000' + pass;
    return crypto.subtle.importKey('raw', enc.encode(material), 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' }, base,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    });
  }
  function sealWith(key, salt, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(JSON.stringify(obj))).then(function (ct) {
      return JSON.stringify({ app: 'masroufi', v: 2, setup: obj.setup === true, kdf: { alg: 'PBKDF2-SHA256', iter: KDF_ITER, salt: b64(salt) }, iv: b64(iv), ct: b64(ct) });
    });
  }
  function vaultIsSetup() { try { return JSON.parse(storageGet(VAULT_KEY) || '{}').setup === true; } catch (e) { return false; } }
  function createDefaultVault() {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var st = emptyState(); st.setup = true;
    return deriveKey(DEFAULT_USER, DEFAULT_PASS, salt, KDF_ITER).then(function (key) { return sealWith(key, salt, st); })
      .then(function (box) { if (!storageSet(VAULT_KEY, box)) throw new Error('storage'); });
  }
  function openVault(text, user, pass) {
    var box = JSON.parse(text);
    if (!box || box.app !== 'masroufi' || !box.kdf || !box.iv || !box.ct) throw new Error('bad');
    var iter = box.kdf.iter;
    if (!Number.isInteger(iter) || iter < 100000 || iter > 5000000) throw new Error('bad');
    var salt = unb64(box.kdf.salt);
    return deriveKey(user, pass, salt, iter).then(function (key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct)).then(function (pt) {
        return { key: key, salt: salt, iter: iter, state: normalize(JSON.parse(dec.decode(pt))) };
      });
    });
  }

  var saving = Promise.resolve();
  function persist() {
    if (!session.key) return Promise.resolve();
    var key = session.key, salt = session.salt, snapshot = session.state;
    saving = saving.then(function () {
      return sealWith(key, salt, snapshot).then(function (box) {
        if (!storageSet(VAULT_KEY, box)) toast('تعذّر الحفظ في هذا المتصفح. صدّر نسخة احتياطية حتى لا تضيع بياناتك.');
      });
    });
    return saving;
  }

  // حماية من التخمين: تأخير متزايد بعد كل محاولة خاطئة (محفوظ محليًا)
  function guard() {
    try { var g = JSON.parse(storageGet(GUARD_KEY) || '{}'); return { fails: g.fails | 0, until: +g.until || 0 }; }
    catch (e) { return { fails: 0, until: 0 }; }
  }
  function guardFail() {
    var g = guard(); g.fails += 1;
    var wait = g.fails < 3 ? 0 : Math.min(15 * 60, 5 * Math.pow(2, g.fails - 3));
    g.until = Date.now() + wait * 1000;
    storageSet(GUARD_KEY, JSON.stringify(g));
    return wait;
  }
  function guardReset() { storageDel(GUARD_KEY); }

  // ---------------------------------------------------------------- القفل التلقائي
  var idleTimer = null;
  function bumpIdle() {
    if (!session.key) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(function () { lock('قُفل التطبيق تلقائيًا بعد مدة من عدم الاستخدام.'); }, session.state.profile.lockMinutes * 60000);
  }
  ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(function (ev) {
    document.addEventListener(ev, bumpIdle, { passive: true, capture: true });
  });

  function lock(reason) {
    saving.then(function () {
      clearTimeout(idleTimer);
      session.key = null; session.salt = null; session.state = null; session.user = null;
      ui = freshUi();
      renderLock(reason);
    });
  }

  // ---------------------------------------------------------------- واجهة
  var root = $('app');
  function freshUi() { return { tab: 'dash', month: mkey(today()), confirm: null, review: null, msgs: {}, backupText: '' }; }
  var ui = freshUi();

  var toastTimer = null;
  function toast(text) {
    var t = $('toast');
    if (!t) { t = el('div', { id: 'toast', class: 'toast', role: 'status' }); document.body.appendChild(t); }
    t.textContent = text; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 3200);
  }

  // ---------- أيقونات (SVG تُبنى بـ DOM، بدون innerHTML)
  var SVGNS = 'http://www.w3.org/2000/svg';
  var ICONS = {
    dash: 'M4 4h7v8H4z M13 4h7v5h-7z M13 11h7v9h-7z M4 14h7v6H4z',
    income: 'M12 3v11 M7.5 9.5L12 14l4.5-4.5 M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4',
    exp: 'M6 3h12v18l-3-2-3 2-3-2-3 2z M9 8h6 M9 12h6 M9 16h3',
    debts: 'M3 6h18v12H3z M3 10h18 M7 15h4',
    custody: 'M4 8h16v12H4z M9 8V5h6v3 M4 13h16',
    amanat: 'M12 3l8 3v6c0 4.6-3.4 8-8 9-4.6-1-8-4.4-8-9V6z M9 12l2 2 4-4',
    upload: 'M14 3H6v18h12V7z M14 3v4h4 M12 18v-6 M9.5 14.5L12 12l2.5 2.5',
    settings: 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z',
    lock: 'M5 11h14v10H5z M8 11V7a4 4 0 0 1 8 0v4 M12 15v2',
    device: 'M7 3h10v18H7z M11 18h2',
    timer: 'M12 8v5l3 2 M21 13a9 9 0 1 1-18 0 9 9 0 0 1 18 0z M10 2h4',
    prev: 'M9 6l6 6-6 6',
    next: 'M15 6l-6 6 6 6',
    plus: 'M12 5v14 M5 12h14',
    alert: 'M12 4l9 16H3z M12 10v4 M12 17h.01',
    check: 'M5 12.5l4.5 4.5L19 7.5',
    info: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z M12 11v5 M12 8h.01',
    eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0z',
    eyeoff: 'M3 3l18 18 M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1 M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 5.4-1.6 M9.9 9.9a3 3 0 0 0 4.2 4.2',
    wallet: 'M3 7h17v13H3z M3 7l13-4v4 M16 13.5h1.5',
    trend: 'M3 17l6-6 4 4 8-8 M15 7h6v6',
    user: 'M16 8a4 4 0 1 1-8 0 4 4 0 0 1 8 0z M4 21c1-4 4-6 8-6s7 2 8 6',
    key: 'M15 8a4 4 0 1 1-8 0 4 4 0 0 1 8 0z M13.5 11L21 18.5 M18 15.5l2-2',
    trash: 'M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13',
    logout: 'M15 4h4v16h-4 M10 8l-4 4 4 4 M6 12h10',
    file: 'M14 3H6v18h12V7z M14 3v4h4 M9 13h6 M9 17h4',
    inbox: 'M3 13l3-8h12l3 8v6H3z M3 13h5l1 3h6l1-3h5'
  };
  function icon(name) {
    var s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'ic'); s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
    var p = document.createElementNS(SVGNS, 'path'); p.setAttribute('d', ICONS[name] || ICONS.info);
    s.appendChild(p); return s;
  }
  function sv(tag, attrs, text) {
    var n = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, String(attrs[k])); });
    if (text !== undefined) n.textContent = String(text);
    return n;
  }
  function emptyOf(ic, text) { return el('div', { class: 'empty' }, icon(ic), el('span', null, text)); }

  // ---------- شاشة الدخول
  function lockShell(card) {
    var side = el('section', { class: 'lock-side', 'aria-label': 'عن مصروفي' },
      el('div', { class: 'brand' }, el('div', { class: 'brand-mark', 'aria-hidden': 'true' }, 'م'),
        el('div', null, el('div', { class: 'brand-name' }, 'مصروفي'), el('div', { class: 'brand-sub' }, 'مصروفك الشخصي، مفصول عن العهد والأمانات'))),
      el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '16px', position: 'relative', 'z-index': '1' } },
        el('h1', null, 'رصيد حسابك ', el('em', null, 'ليس كله لك')),
        el('p', { class: 'lede' }, 'اعرف كم لك فعليًا، وكم عندك من عهد وأمانات، ووين يروح مصروفك كل شهر.')),
      el('ul', { class: 'lock-facts' },
        el('li', null, icon('lock'), el('span', null, 'كل بياناتك مشفّرة بـ AES-256 قبل ما تُحفظ.')),
        el('li', null, icon('device'), el('span', null, 'تبقى على جهازك فقط، بدون خادم ولا أي اتصال خارجي.')),
        el('li', null, icon('timer'), el('span', null, 'تُقفل المنصة تلقائيًا إذا تركتها مفتوحة.'))));
    root.replaceChildren(el('div', { class: 'lock' }, side, el('main', { class: 'lock-main' }, card)));
  }

  // حقل كلمة مرور مع زر إظهار/إخفاء
  function pwField(id, label, autocomplete, hint) {
    var inp = el('input', { id: id, type: 'password', autocomplete: autocomplete, maxlength: '128', dir: 'ltr', required: true, spellcheck: 'false' });
    var tog = el('button', { type: 'button', class: 'btn ghost icon', 'aria-label': 'إظهار كلمة المرور', 'aria-pressed': 'false' }, icon('eye'));
    tog.addEventListener('click', function () {
      var show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      tog.setAttribute('aria-pressed', show ? 'true' : 'false');
      tog.setAttribute('aria-label', show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور');
      tog.replaceChildren(icon(show ? 'eyeoff' : 'eye'));
    });
    var wrap = el('div', { class: 'field' }, el('label', { for: id }, label),
      el('div', { css: { display: 'flex', gap: '8px', 'align-items': 'center' } }, inp, tog),
      hint ? el('span', { class: 'hint' }, hint) : null);
    return { wrap: wrap, input: inp };
  }

  function renderLock(reason) {
    if (!cryptoReady()) {
      lockShell(el('div', { class: 'lock-card' }, el('h2', null, 'المتصفح غير مدعوم'),
        el('p', { class: 'msg err' }, 'هذا المتصفح لا يدعم التشفير المطلوب. افتح المنصة عبر https أو من متصفح حديث.')));
      return;
    }
    if (!storageGet(VAULT_KEY)) {
      lockShell(el('div', { class: 'lock-card' }, el('h2', null, 'جارٍ تجهيز المنصة…'), el('p', { class: 'lead' }, 'نجهّز خزنة مشفّرة على هذا الجهاز.')));
      createDefaultVault().then(function () { renderLock(reason); }).catch(function () {
        lockShell(el('div', { class: 'lock-card' }, el('h2', null, 'تعذّر التجهيز'),
          el('p', { class: 'msg err' }, 'هذا المتصفح يمنع الحفظ (ربما وضع التصفح الخاص). جرّب نافذة عادية.')));
      });
      return;
    }
    var first = vaultIsSetup();
    var msg = el('p', { class: reason ? 'msg' : 'msg err', role: 'alert' }, reason || '');
    var user = el('input', { id: 'login-user', type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', maxlength: '32', dir: 'ltr', required: true });
    var pw = pwField('login-pass', 'كلمة المرور', 'current-password');
    var btn = el('button', { class: 'btn block', type: 'submit' }, 'دخول');
    var form = el('form', { autocomplete: 'on', css: { display: 'flex', 'flex-direction': 'column', gap: '14px' } },
      el('div', { class: 'field' }, el('label', { for: 'login-user' }, 'اسم المستخدم'), user), pw.wrap, btn, msg);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      msg.className = 'msg err'; msg.textContent = '';
      var g = guard();
      if (g.until > Date.now()) { msg.textContent = 'محاولات كثيرة خاطئة. حاول بعد ' + Math.ceil((g.until - Date.now()) / 1000) + ' ثانية.'; return; }
      var u = normUser(user.value), p = pw.input.value;
      if (!u || !p) { msg.textContent = 'اكتب اسم المستخدم وكلمة المرور.'; return; }
      btn.disabled = true; btn.textContent = 'جارٍ التحقق…';
      Promise.resolve().then(function () { return openVault(storageGet(VAULT_KEY), u, p); }).then(function (r) {
        guardReset();
        session.key = r.key; session.salt = r.salt; session.state = r.state; session.user = u;
        pw.input.value = '';
        if (r.iter !== KDF_ITER) persist();
        bumpIdle();
        if (session.state.setup) renderSetup(); else render();
      }).catch(function () {
        var w = guardFail();
        btn.disabled = false; btn.textContent = 'دخول';
        msg.textContent = 'اسم المستخدم أو كلمة المرور غير صحيحة' + (w ? '. انتظر ' + w + ' ثانية قبل المحاولة التالية.' : '.');
        pw.input.select();
      });
    });
    var card = el('div', { class: 'lock-card' },
      el('div', null, el('div', { class: 'eyebrow' }, 'تسجيل الدخول'), el('h2', null, 'أهلًا بك في مصروفي')),
      el('p', { class: 'lead' }, 'ادخل باسم المستخدم وكلمة المرور.'),
      first ? el('div', { class: 'callout mid' }, icon('info'), el('div', null, el('strong', null, 'أول دخول؟'),
        el('span', null, 'استخدم بيانات الدخول الافتراضية، وبعدها تختار اسم المستخدم وكلمة المرور الخاصة فيك.'))) : null,
      form,
      first ? null : wipeBlock('lockwipe', 'نسيت كلمة المرور؟'));
    lockShell(card);
    user.focus();
  }

  // تقييم بسيط لقوة كلمة المرور
  function pwScore(p, u) {
    if (!p) return 0;
    var s = 0;
    if (p.length >= 10) s++;
    if (p.length >= 14) s++;
    if (/[a-z؀-ۿ]/i.test(p) && /\d/.test(p)) s++;
    if (/[^A-Za-z0-9؀-ۿ]/.test(p) || /[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
    if (u && p.toLowerCase().indexOf(u) >= 0) s = Math.min(s, 1);
    return Math.min(4, s);
  }
  function checkNewCreds(u, p, p2) {
    if (!USER_RE.test(u)) return 'اسم المستخدم من 3 إلى 32 حرفًا: حروف إنجليزية صغيرة أو أرقام أو . _ -';
    if (u === DEFAULT_USER) return 'اختر اسم مستخدم غير الاسم الافتراضي.';
    if (p.length < 10) return 'كلمة المرور 10 أحرف على الأقل.';
    if (!(/[a-z؀-ۿ]/i.test(p) && /\d/.test(p))) return 'كلمة المرور لازم يكون فيها حروف وأرقام.';
    if (p === DEFAULT_PASS) return 'اختر كلمة مرور غير الكلمة الافتراضية.';
    if (p.toLowerCase().indexOf(u) >= 0) return 'لا تضع اسم المستخدم داخل كلمة المرور.';
    if (p !== p2) return 'كلمتا المرور غير متطابقتين.';
    return null;
  }
  function strengthMeter(input, userInput) {
    var labels = ['', 'ضعيفة', 'مقبولة', 'جيدة', 'قوية'];
    var colors = ['var(--line)', 'var(--red)', 'var(--brass)', 'var(--green-bar)', 'var(--green)'];
    var fill = el('span', { css: { width: '0%' } });
    var txt = el('span', { class: 'hint', 'aria-live': 'polite' });
    var upd = function () {
      var s = pwScore(input.value, normUser(userInput ? userInput.value : ''));
      fill.style.setProperty('width', (s * 25) + '%'); fill.style.setProperty('background', colors[s]);
      txt.textContent = s ? 'قوة كلمة المرور: ' + labels[s] : '';
    };
    input.addEventListener('input', upd); if (userInput) userInput.addEventListener('input', upd);
    return el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '4px' } }, el('div', { class: 'bar' }, fill), txt);
  }

  // ---------- أول دخول: إجبار تغيير بيانات الدخول الافتراضية
  function renderSetup() {
    var msg = el('p', { class: 'msg err', role: 'alert' });
    var user = el('input', { id: 'setup-user', type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', maxlength: '32', dir: 'ltr', required: true });
    var p1 = pwField('setup-pass', 'كلمة المرور الجديدة', 'new-password', '10 أحرف على الأقل، فيها حروف وأرقام. الأفضل جملة طويلة تتذكرها.');
    var p2 = pwField('setup-pass2', 'أعد كتابة كلمة المرور', 'new-password');
    var demo = el('input', { id: 'setup-demo', type: 'checkbox', checked: true });
    var btn = el('button', { class: 'btn block', type: 'submit' }, 'حفظ والدخول');
    var form = el('form', { css: { display: 'flex', 'flex-direction': 'column', gap: '14px' } },
      el('div', { class: 'field' }, el('label', { for: 'setup-user' }, 'اسم المستخدم الجديد'), user,
        el('span', { class: 'hint' }, 'حروف إنجليزية صغيرة أو أرقام أو . _ - (من 3 إلى 32)')),
      p1.wrap, strengthMeter(p1.input, user), p2.wrap,
      el('label', { for: 'setup-demo', css: { display: 'flex', gap: '10px', 'align-items': 'center', 'font-size': '14px' } }, demo, 'ابدأ ببيانات توضيحية (تقدر تمسحها بضغطة)'),
      btn, msg);
    form.addEventListener('submit', function (e) {
      e.preventDefault(); msg.textContent = '';
      var u = normUser(user.value), p = p1.input.value;
      var err = checkNewCreds(u, p, p2.input.value);
      if (err) { msg.textContent = err; return; }
      btn.disabled = true; btn.textContent = 'جارٍ التشفير…';
      var salt = crypto.getRandomValues(new Uint8Array(16));
      deriveKey(u, p, salt, KDF_ITER).then(function (key) {
        var keepLock = session.state.profile.lockMinutes;
        var st = demo.checked ? demoState() : emptyState();
        st.setup = false; st.profile.lockMinutes = keepLock;
        session.key = key; session.salt = salt; session.state = st; session.user = u;
        p1.input.value = ''; p2.input.value = '';
        return persist();
      }).then(function () { bumpIdle(); render(); toast('تم. من الآن تدخل باسم المستخدم «' + u + '» وكلمة المرور الجديدة.'); })
        .catch(function () { btn.disabled = false; btn.textContent = 'حفظ والدخول'; msg.textContent = 'تعذّر الحفظ في هذا المتصفح.'; });
    });
    lockShell(el('div', { class: 'lock-card' },
      el('div', null, el('div', { class: 'eyebrow' }, 'خطوة واحدة قبل البدء'), el('h2', null, 'اختر بيانات دخولك')),
      el('p', { class: 'lead' }, 'بيانات الدخول الافتراضية معروفة، فلازم تغيّرها قبل ما تضيف أي بيانات. ما فيه طريقة لاسترجاع كلمة المرور إذا نسيتها، فاحفظها في مكان آمن.'),
      form,
      el('button', { type: 'button', class: 'linkbtn', onclick: function () { lock(); } }, 'خروج')));
    user.focus();
  }

  function wipeBlock(id, label) {
    var box = el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '10px' } });
    var open = false;
    var draw = function () {
      box.replaceChildren();
      if (!open) { box.appendChild(el('button', { type: 'button', class: 'linkbtn', onclick: function () { open = true; draw(); } }, label)); return; }
      var inp = el('input', { id: id, type: 'text', autocomplete: 'off' });
      box.appendChild(el('div', { class: 'callout warn' }, icon('alert'), el('div', null, el('strong', null, 'حذف كل البيانات'),
        el('span', null, 'ما فيه طريقة لفتح البيانات بدون كلمة المرور. الحل الوحيد حذفها من هذا الجهاز، وبعدها تدخل بالبيانات الافتراضية من جديد (أو تستعيد نسخة احتياطية).'))));
      box.appendChild(el('div', { class: 'field' }, el('label', { for: id }, 'اكتب كلمة «احذف» للتأكيد'), inp));
      box.appendChild(el('div', { class: 'row', css: { gap: '8px' } },
        el('button', { type: 'button', class: 'btn danger small', onclick: function () {
          if (cleanText(inp.value) !== 'احذف') { inp.focus(); return; }
          storageDel(VAULT_KEY); guardReset();
          session.key = null; session.state = null; session.user = null; ui = freshUi();
          renderLock('حُذفت البيانات من هذا الجهاز. ادخل بالبيانات الافتراضية.');
        } }, icon('trash'), 'حذف كل البيانات'),
        el('button', { type: 'button', class: 'btn ghost small', onclick: function () { open = false; draw(); } }, 'إلغاء')));
      inp.focus();
    };
    draw();
    return box;
  }

  // ---------- الحسابات
  function S() { return session.state; }
  function personalOf(k) { return sum(S().expenses.filter(function (x) { return mkey(x.date) === k; }), function (x) { return x.amount; }); }
  function fixedIncomeOf(k) { return sum(S().sources.filter(function (x) { return x.since <= k; }), function (x) { return x.amount; }); }
  function otherIncomeOf(k) { return sum(S().incomes.filter(function (x) { return mkey(x.date) === k; }), function (x) { return x.amount; }); }
  function debtPaid(d) { return Math.min(d.total, d.paid + sum(d.payments, function (p) { return p.amount; })); }
  function activeDebts(dir) { return S().debts.filter(function (d) { return d.dir === dir && debtPaid(d) < d.total; }); }
  function entIn(e) { return sum(e.moves.filter(function (m) { return m.dir === 'in'; }), function (m) { return m.amount; }); }
  function entOut(e) { return sum(e.moves.filter(function (m) { return m.dir === 'out'; }), function (m) { return m.amount; }); }
  function entBal(e) { return entIn(e) - entOut(e); }
  function ents(type) { return S().entities.filter(function (e) { return e.type === type; }); }
  function heldOf(type) { return sum(ents(type).filter(function (e) { return !e.closed; }), function (e) { return Math.max(0, entBal(e)); }); }
  function monthlyInstallments() { return sum(activeDebts('on'), function (d) { return d.monthly; }); }
  function catTotals(k) {
    var t = {}; CATS.forEach(function (c) { t[c] = 0; });
    S().expenses.forEach(function (x) { if (mkey(x.date) === k) t[x.cat] += x.amount; });
    return t;
  }
  // متوسط كل تصنيف في الأشهر السابقة التي فيها بيانات (حتى 6 أشهر)
  function catAverages(k) {
    var prev = [];
    for (var i = 1; i <= 6; i++) { var pk = addMonths(k, -i); if (personalOf(pk) > 0) prev.push(pk); }
    var avg = {}; CATS.forEach(function (c) { avg[c] = 0; });
    if (!prev.length) return { avg: avg, n: 0, total: 0 };
    prev.forEach(function (pk) { var t = catTotals(pk); CATS.forEach(function (c) { avg[c] += t[c] / prev.length; }); });
    return { avg: avg, n: prev.length, total: sum(prev.map(personalOf)) / prev.length };
  }

  // ---------- مكوّنات صغيرة
  function stat(label, value, foot, opts) {
    opts = opts || {};
    return el('div', { class: 'stat' + (opts.hero ? ' hero' : '') },
      el('div', { class: 'top' }, el('span', { class: 'label' }, label), opts.icon ? el('span', { class: 'chip' }, icon(opts.icon)) : null),
      el('span', { class: 'value ' + (opts.color || '') }, value, opts.unit === false ? null : el('small', null, 'ر.س')),
      foot ? el('span', { class: 'foot' }, foot) : null);
  }
  function bar(pct, kind) {
    return el('div', { class: 'bar ' + (kind || ''), role: 'img', 'aria-label': Math.round(pct) + '%' },
      el('span', { css: { width: Math.max(0, Math.min(100, pct)) + '%' } }));
  }
  function field(id, label, input, wide, hint) {
    input.id = id;
    return el('div', { class: 'field' + (wide ? ' wide' : '') }, el('label', { for: id }, label), input, hint ? el('span', { class: 'hint' }, hint) : null);
  }
  function txtInput(ph, max) { return el('input', { type: 'text', placeholder: ph || '', maxlength: String(max || MAX_TEXT), autocomplete: 'off' }); }
  function amtInput() { return el('input', { type: 'text', inputmode: 'decimal', placeholder: '0', maxlength: '14', autocomplete: 'off', dir: 'ltr' }); }
  function dateInput(v) { return el('input', { type: 'date', value: v || today(), min: '2000-01-01', max: '2100-12-31' }); }
  function select(options, value) {
    var s = el('select');
    options.forEach(function (o) { s.appendChild(el('option', { value: o[0], selected: o[0] === value }, o[1])); });
    return s;
  }
  function msgEl(key) {
    var m = ui.msgs[key];
    return el('p', { class: 'msg ' + (m ? (m.ok ? 'ok' : 'err') : ''), role: 'status' }, m ? m.text : '');
  }
  function say(key, ok, text) { ui.msgs = {}; ui.msgs[key] = { ok: ok, text: text }; }
  function commit(key, text) { say(key, true, text); persist(); render(); }
  function fail(key, text) { say(key, false, text); render(); }
  function sectionTitle(ic, text) { return el('div', { class: 'card-title' }, icon(ic), el('h2', null, text)); }
  function composer(ic, title) {
    var c = el('div', { class: 'composer' }, el('h3', null, icon(ic), title));
    for (var i = 2; i < arguments.length; i++) append(c, arguments[i]);
    return c;
  }

  // زر حذف بخطوتي تأكيد
  function delBtn(id, label, onYes) {
    if (ui.confirm === id) {
      return el('span', { class: 'row', css: { gap: '6px' } },
        el('button', { type: 'button', class: 'btn danger small', onclick: function () { ui.confirm = null; onYes(); persist(); render(); } }, 'تأكيد الحذف'),
        el('button', { type: 'button', class: 'btn ghost small', onclick: function () { ui.confirm = null; render(); } }, 'إلغاء'));
    }
    return el('button', { type: 'button', class: 'btn ghost icon', 'aria-label': 'حذف ' + label, title: 'حذف', onclick: function () { ui.confirm = id; render(); } }, icon('trash'));
  }
  function kindPill(k) {
    var map = { p: 'شخصي', c: 'عهدة', a: 'أمانة', in: 'دخل' };
    return el('span', { class: 'pill ' + k }, map[k]);
  }

  // ---------- الإطار العام
  var TABS = [
    { id: 'dash', group: 'عام', icon: 'dash', label: 'لوحة التحكم', sub: function () { return 'ملخص وضعك المالي لشهر ' + monthName(ui.month); } },
    { id: 'income', group: 'عام', icon: 'income', label: 'الإيرادات', sub: function () { return 'رواتبك ودخلك من كل مصدر'; }, count: function () { return S().sources.length; } },
    { id: 'exp', group: 'عام', icon: 'exp', label: 'المصروفات', sub: function () { return 'مصروف الشهر مقسّم حسب نوعه'; } },
    { id: 'debts', group: 'الالتزامات', icon: 'debts', label: 'الديون', sub: function () { return 'المسدَّد والمتبقي، واللي لك عند الآخرين'; }, count: function () { return activeDebts('on').length; } },
    { id: 'custody', group: 'الالتزامات', icon: 'custody', label: 'العهد', sub: function () { return 'مبالغ مستلمة تصرفها نيابة عن جهاتها'; }, count: function () { return ents('c').filter(function (e) { return !e.closed; }).length; } },
    { id: 'amanat', group: 'الالتزامات', icon: 'amanat', label: 'الأمانات', sub: function () { return 'مبالغ محفوظة عندك لجهات أخرى'; }, count: function () { return ents('a').length; } },
    { id: 'upload', group: 'أدوات', icon: 'upload', label: 'استيراد الكشف', sub: function () { return 'اقرأ كشف الشهر داخل جهازك وراجع التصنيف قبل الاعتماد'; } },
    { id: 'settings', group: 'أدوات', icon: 'settings', label: 'الإعدادات والأمان', sub: function () { return 'بيانات الدخول والنسخ الاحتياطي والقفل التلقائي'; } }
  ];

  function render() {
    if (!session.state) { renderLock(); return; }
    if (session.state.setup) { renderSetup(); return; }
    var y = window.scrollY;
    var tab = TABS.filter(function (t) { return t.id === ui.tab; })[0] || TABS[0];
    var nav = el('nav', { class: 'nav', 'aria-label': 'أقسام المنصة' });
    var lastGroup = '';
    TABS.forEach(function (t) {
      if (t.group !== lastGroup) { nav.appendChild(el('div', { class: 'nav-label', 'aria-hidden': 'true' }, t.group)); lastGroup = t.group; }
      var c = t.count ? t.count() : 0;
      nav.appendChild(el('button', { type: 'button', 'aria-current': t.id === ui.tab ? 'page' : null,
        onclick: function () { ui.tab = t.id; ui.msgs = {}; ui.confirm = null; render(); window.scrollTo(0, 0); } },
        icon(t.icon), el('span', null, t.label), c ? el('span', { class: 'count num' }, c) : null));
    });
    var doLock = function () { lock('قفلت المنصة. ادخل من جديد للمتابعة.'); };
    var payday = S().sources.filter(function (s) { return s.day; })[0];
    var rail = el('aside', { class: 'rail' },
      el('div', { class: 'rail-top' },
        el('div', { class: 'brand' }, el('div', { class: 'brand-mark', 'aria-hidden': 'true' }, 'م'),
          el('div', null, el('div', { class: 'brand-name' }, 'مصروفي'), el('div', { class: 'brand-sub' }, S().profile.name || session.user || ''))),
        el('button', { type: 'button', class: 'lock-btn icon-only', 'aria-label': 'قفل المنصة', onclick: doLock }, icon('lock'))),
      nav,
      el('div', { class: 'rail-foot' },
        el('div', { class: 'payday' },
          el('span', { class: 'k' }, payday ? 'موعد الراتب' : 'ابدأ من هنا'),
          el('span', { class: 'v' }, payday ? nextPay(payday.day) : 'أضف رواتبك'),
          el('p', null, 'بعد نزول الراتب صدّر كشف الشهر واستورده، والمنصة تفصل لك الشخصي عن العهد والأمانات.')),
        el('button', { type: 'button', class: 'lock-btn', onclick: doLock }, icon('lock'), 'قفل المنصة')));

    var tools = null;
    if (['dash', 'income', 'exp'].indexOf(tab.id) >= 0) {
      var cur = mkey(today());
      var monthSel = select(monthOptions(), ui.month);
      monthSel.id = 'month-pick';
      monthSel.setAttribute('aria-label', 'الشهر');
      monthSel.addEventListener('change', function () { ui.month = monthSel.value; render(); });
      tools = el('div', { class: 'stepper' },
        el('button', { type: 'button', 'aria-label': 'الشهر السابق', onclick: function () { ui.month = addMonths(ui.month, -1); render(); } }, icon('prev')),
        monthSel,
        el('button', { type: 'button', 'aria-label': 'الشهر التالي', disabled: ui.month >= cur, onclick: function () { ui.month = addMonths(ui.month, 1); render(); } }, icon('next')));
    }
    var head = el('div', { class: 'head' },
      el('div', null, el('div', { class: 'eyebrow' }, tab.group), el('h1', null, tab.label), el('div', { class: 'sub' }, tab.sub())), tools);

    var inner = el('div', { class: 'main-inner' }, head);
    if (S().demo) {
      inner.appendChild(el('div', { class: 'demo-banner' }, el('span', null, icon('info'), 'أرقام توضيحية. امسحها وابدأ ببياناتك'),
        el('button', { type: 'button', class: 'btn small dark', onclick: function () {
          var p = S().profile; session.state = emptyState(); session.state.profile.lockMinutes = p.lockMinutes; session.state.profile.name = p.name;
          persist(); render(); toast('مُسحت البيانات التوضيحية.');
        } }, 'ابدأ ببياناتي')));
    }
    inner.appendChild(({ dash: viewDash, income: viewIncome, exp: viewExp, debts: viewDebts, custody: viewCustody, amanat: viewAmanat, upload: viewUpload, settings: viewSettings })[tab.id]());
    root.replaceChildren(el('div', { class: 'app' }, rail, el('main', { class: 'main' }, inner)));
    window.scrollTo(0, y);
  }

  function monthOptions() {
    var cur = mkey(today()), set = {};
    for (var i = 0; i < 12; i++) set[addMonths(cur, -i)] = 1;
    S().expenses.forEach(function (x) { set[mkey(x.date)] = 1; });
    S().incomes.forEach(function (x) { set[mkey(x.date)] = 1; });
    set[ui.month] = 1;
    return Object.keys(set).filter(function (k) { return k <= cur || k === ui.month; }).sort().reverse().map(function (k) { return [k, monthName(k)]; });
  }

  // ---------- لوحة التحكم
  function viewDash() {
    var k = ui.month;
    var spent = personalOf(k);
    var av = catAverages(k);
    var inc = fixedIncomeOf(k) + otherIncomeOf(k);
    var inst = monthlyInstallments();
    var debtRem = sum(activeDebts('on'), function (d) { return d.total - debtPaid(d); });
    var custody = heldOf('c'), amanat = heldOf('a');
    var openC = ents('c').filter(function (e) { return !e.closed && entBal(e) > 0; }).length;
    var diff = av.total ? Math.round((spent - av.total) / av.total * 100) : null;
    var t = catTotals(k);
    var topCat = CATS.slice().sort(function (a, b) { return t[b] - t[a]; })[0];
    var txCount = S().expenses.filter(function (x) { return mkey(x.date) === k; }).length;

    var wrap = el('div', { class: 'stack' });
    var hero = el('div', { class: 'stat hero' },
      el('div', { class: 'top' }, el('span', { class: 'label' }, 'مصروفك الشخصي في ' + monthName(k)), el('span', { class: 'chip' }, icon('wallet'))),
      el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '10px' } },
        el('span', { class: 'value' }, fmt(spent), el('small', null, 'ر.س')),
        diff === null ? el('span', { class: 'delta flat' }, 'لا توجد أشهر سابقة للمقارنة')
          : el('span', { class: 'delta ' + (diff > 2 ? 'up' : diff < -2 ? 'down' : 'flat') }, (diff > 0 ? 'أعلى' : 'أقل') + ' من متوسطك بـ ' + Math.abs(diff) + '%')),
      el('div', { class: 'hero-meta' },
        el('div', null, 'متوسطك الشهري', el('strong', null, av.total ? fmt(av.total) : '—')),
        el('div', null, 'عدد العمليات', el('strong', null, txCount)),
        el('div', null, 'أكبر بند', el('strong', null, t[topCat] ? topCat : '—'))));
    wrap.appendChild(el('div', { class: 'kpis' }, hero,
      stat('دخلك هذا الشهر', fmt(inc), 'الفائض بعد المصروف والأقساط ' + fmt(inc - spent - inst), { color: 'c-green', icon: 'income' }),
      stat('المتبقي من الديون', fmt(debtRem), 'أقساط شهرية ' + fmt(inst) + ' ر.س', { icon: 'debts' }),
      stat('عهد مفتوحة عندك', fmt(custody), openC ? openC + ' عهدة تحتاج تصفية' : 'لا توجد عهد مفتوحة', { color: 'c-brass', icon: 'custody' }),
      stat('أمانات محفوظة عندك', fmt(amanat), ents('a').filter(function (e) { return entBal(e) > 0; }).length + ' جهة', { color: 'c-green', icon: 'amanat' })));

    // الرصيد ليس كله لك
    var bal = S().profile.balance;
    var mine = bal - custody - amanat;
    var balCard = el('section', { class: 'card' },
      el('div', { class: 'card-head' }, sectionTitle('wallet', 'رصيد حسابك ليس كله لك'), el('span', { class: 'meta num' }, 'الرصيد الحالي ' + fmt(bal) + ' ر.س')));
    if (bal > 0) {
      var tot = Math.max(bal, custody + amanat);
      balCard.appendChild(el('div', { class: 'split', role: 'img', 'aria-label': 'لك ' + fmt(Math.max(0, mine)) + '، عهد ' + fmt(custody) + '، أمانات ' + fmt(amanat) },
        mine > 0 ? el('span', { css: { width: (mine / tot * 100) + '%', background: 'var(--hero)' } }) : null,
        custody > 0 ? el('span', { css: { width: (custody / tot * 100) + '%', background: 'var(--brass)' } }) : null,
        amanat > 0 ? el('span', { css: { width: (amanat / tot * 100) + '%', background: 'var(--green-bar)' } }) : null));
      var leg = function (color, label, v, share) {
        return el('div', null, el('span', { class: 'k' }, el('i', { class: 'sw', css: { background: color } }), label),
          el('span', { class: 'v' }, fmt(v), el('small', null, ' ر.س · ' + Math.round(Math.max(0, v) / tot * 100) + '%')));
      };
      balCard.appendChild(el('div', { class: 'legend' },
        leg('var(--hero)', 'لك فعليًا', mine), leg('var(--brass)', 'عهد', custody), leg('var(--green-bar)', 'أمانات', amanat)));
      if (mine < 0) balCard.appendChild(el('div', { class: 'callout warn' }, icon('alert'), el('div', null, el('strong', null, 'رصيدك أقل من العهد والأمانات'), el('span', null, 'صرفت ' + fmt(-mine) + ' ر.س من أموال غيرك. رتّب تعويضها قبل التصفية.'))));
    } else {
      balCard.appendChild(emptyOf('wallet', 'اكتب رصيد حسابك الحالي، ونوريك كم منه لك فعليًا بعد العهد والأمانات.'));
    }
    var balIn = amtInput(); balIn.value = bal ? String(bal) : '';
    balCard.appendChild(composer('wallet', 'تحديث الرصيد',
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault(); var a = parseAmount(balIn.value, true);
        if (a === null) return fail('bal', 'اكتب الرصيد رقمًا صحيحًا (حتى منزلتين عشريتين).');
        S().profile.balance = a; commit('bal', 'حُدّث الرصيد.');
      } }, field('bal-in', 'رصيد حسابك الحالي (ر.س)', balIn), el('button', { class: 'btn dark', type: 'submit' }, 'حفظ')), msgEl('bal')));
    wrap.appendChild(balCard);

    // المخطط + وين الخلل
    var cols = [];
    for (var i = 11; i >= 0; i--) cols.push(addMonths(k, -i));
    var vals = cols.map(personalOf);
    wrap.appendChild(el('div', { class: 'row' },
      el('section', { class: 'card', css: { flex: '3 1 440px' } },
        el('div', { class: 'card-head' }, sectionTitle('trend', 'مصروفك آخر 12 شهرًا'),
          el('div', { class: 'chart-legend' }, el('span', null, el('i', { class: 'sw', css: { background: 'var(--brass)' } }), 'الشهر المختار'),
            av.total ? el('span', null, el('i', { class: 'dash-sw' }), 'متوسطك') : null)),
        chartSvg(cols, vals, k, av.total)),
      el('section', { class: 'card', css: { flex: '2 1 300px' } }, sectionTitle('alert', 'وين الخلل هذا الشهر؟'), insights(k, av))));

    // الديون
    var dl = activeDebts('on');
    var dCard = el('section', { class: 'card' }, el('div', { class: 'card-head' }, sectionTitle('debts', 'المتبقي من كل دين'), el('span', { class: 'meta num' }, 'الإجمالي ' + fmt(debtRem) + ' ر.س')));
    if (!dl.length) dCard.appendChild(emptyOf('check', 'لا توجد ديون قائمة. تقدر تضيفها من صفحة الديون.'));
    else dCard.appendChild(el('div', { class: 'grid', css: { 'grid-template-columns': 'repeat(auto-fit, minmax(230px, 1fr))' } }, dl.map(function (d) {
      var p = debtPaid(d), pct = p / d.total * 100;
      return el('div', { class: 'debt-card' },
        el('div', { class: 'card-head' }, el('strong', null, d.name), el('span', { class: 'pill ok num' }, Math.round(pct) + '%')),
        el('span', { class: 'rem' }, fmt(d.total - p), el('small', null, 'ر.س متبقي')),
        bar(pct), el('span', { css: { 'font-size': '12px', color: 'var(--muted)' } }, 'قسط ' + fmt(d.monthly) + (d.end ? ' · ينتهي ' + d.end : '')));
    })));
    wrap.appendChild(dCard);
    return wrap;
  }

  function fmtK(v) { return v >= 1000 ? (v / 1000).toFixed(1) + 'k' : String(Math.round(v)); }
  function chartSvg(cols, vals, k, avg) {
    var W = 640, H = 250, top = 26, base = 206, left = 6, right = 634;
    var max = Math.max.apply(null, vals.concat([avg || 0, 1])) * 1.12;
    var svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'chart-svg', role: 'img', 'aria-label': 'مصروفك الشخصي في آخر 12 شهرًا، الشهر المختار ' + fmt(vals[vals.length - 1]) + ' ر.س' });
    [0.25, 0.5, 0.75].forEach(function (f) { var yy = base - (base - top) * f; svg.appendChild(sv('line', { x1: left, x2: right, y1: yy, y2: yy, class: 'grid-l' })); });
    svg.appendChild(sv('line', { x1: left, x2: right, y1: base, y2: base, class: 'grid-l' }));
    var slot = (right - left) / cols.length, bw = Math.min(30, slot * 0.58);
    cols.forEach(function (c, i) {
      var x = right - (i + 1) * slot + (slot - bw) / 2;
      var h = vals[i] / max * (base - top);
      var g = sv('g');
      g.appendChild(sv('title', {}, monthName(c) + ': ' + fmt(vals[i]) + ' ر.س'));
      if (vals[i] > 0) g.appendChild(sv('rect', { x: x, y: base - Math.max(h, 3), width: bw, height: Math.max(h, 3), rx: 6, class: 'b ' + (c === k ? 'cur' : 'has') }));
      if (vals[i] > 0) g.appendChild(sv('text', { x: x + bw / 2, y: base - h - 7, 'text-anchor': 'middle', class: 'tv' }, fmtK(vals[i])));
      g.appendChild(sv('text', { x: x + bw / 2, y: base + 22, 'text-anchor': 'middle', class: 't' }, monthShort(c)));
      svg.appendChild(g);
    });
    if (avg) {
      var ay = base - avg / max * (base - top);
      svg.appendChild(sv('line', { x1: left, x2: right, y1: ay, y2: ay, class: 'avg' }));
      svg.appendChild(sv('text', { x: left + 2, y: ay - 6, 'text-anchor': 'start', class: 'ta' }, 'المتوسط ' + fmtK(avg)));
    }
    return el('div', { css: { width: '100%' } }, svg);
  }

  function insights(k, av) {
    var box = el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '10px' } });
    if (!av.n) { box.appendChild(emptyOf('info', 'تحتاج شهرًا سابقًا واحدًا على الأقل حتى نقارن مصروفك بمتوسطك.')); return box; }
    var t = catTotals(k);
    var over = [], fine = [];
    CATS.forEach(function (c) {
      if (av.avg[c] < 50) return;
      var d = Math.round((t[c] - av.avg[c]) / av.avg[c] * 100);
      if (d >= 10) over.push({ c: c, d: d }); else fine.push(c);
    });
    over.sort(function (a, b) { return b.d - a.d; });
    over.slice(0, 3).forEach(function (o, i) {
      box.appendChild(el('div', { class: 'callout ' + (i === 0 ? 'warn' : 'mid') }, icon('alert'), el('div', null,
        el('strong', null, o.c + ' أعلى بـ ' + o.d + '%'),
        el('span', { class: 'num' }, 'صرفت ' + fmt(t[o.c]) + ' ر.س مقابل متوسط ' + fmt(av.avg[o.c]) + '.'))));
    });
    if (fine.length) box.appendChild(el('div', { class: 'callout good' }, icon('check'), el('div', null, el('strong', null, over.length ? 'الباقي تحت السيطرة' : 'كل البنود تحت السيطرة'), el('span', null, fine.slice(0, 4).join('، ') + ' ضمن متوسطك أو أقل منه.'))));
    return box;
  }

  // ---------- الإيرادات
  function viewIncome() {
    var k = ui.month;
    var fixed = fixedIncomeOf(k), other = otherIncomeOf(k), total = fixed + other;
    var wrap = el('div', { class: 'stack' });
    wrap.appendChild(el('div', { class: 'grid' },
      stat('إجمالي دخل ' + monthShort(k), fmt(total), null, { hero: true }),
      stat('رواتب ثابتة', fmt(fixed)), stat('إيرادات أخرى', fmt(other)),
      stat('الفائض بعد المصروف والأقساط', fmt(total - personalOf(k) - monthlyInstallments()), null, { color: 'c-green' })));

    var srcCard = el('section', { class: 'card' }, sectionTitle('income', 'مصادر دخلك الثابتة'));
    if (!S().sources.length) srcCard.appendChild(emptyOf('inbox', 'لم تضف أي راتب ثابت بعد.'));
    var g = el('div', { class: 'grid' });
    S().sources.forEach(function (x) {
      var dayIn = el('input', { type: 'number', min: '1', max: '31', value: x.day || '', placeholder: '—', css: { width: '80px' } });
      dayIn.id = 'day-' + x.id;
      dayIn.addEventListener('change', function () {
        var d = parseInt(latinDigits(dayIn.value), 10);
        if (dayIn.value === '') d = 0; else if (!(d >= 1 && d <= 31)) { dayIn.value = x.day || ''; toast('يوم الإيداع بين 1 و31.'); return; }
        x.day = d; persist(); render();
      });
      g.appendChild(el('div', { class: 'card', css: { border: '1px solid var(--line)' } },
        el('div', { class: 'card-head' }, el('strong', null, x.name), el('span', { class: 'pill p' }, x.kind)),
        el('span', { class: 'num c-green', css: { 'font-size': '24px', 'font-weight': '700' } }, fmt(x.amount), el('small', { css: { 'font-size': '13px', color: 'var(--muted)' } }, ' ر.س')),
        bar(total ? x.amount / total * 100 : 0), el('span', { css: { 'font-size': '12px', color: 'var(--muted)' } }, (total ? Math.round(x.amount / total * 100) : 0) + '% من دخلك'),
        el('div', { class: 'row', css: { 'align-items': 'center', gap: '8px', 'border-top': '1px solid var(--line)', 'padding-top': '10px' } },
          el('label', { for: dayIn.id, css: { 'font-size': '13px', 'font-weight': '600' } }, 'يوم الإيداع'), dayIn,
          el('span', { css: { 'font-size': '12px', color: 'var(--muted)' } }, x.day ? 'القادم: ' + nextPay(x.day) : '')),
        el('div', null, delBtn('src-' + x.id, x.name, function () { S().sources = S().sources.filter(function (y) { return y !== x; }); }))));
    });
    srcCard.appendChild(g);
    var sName = txtInput('مثال: جهة العمل'), sKind = select([['راتب شهري', 'راتب شهري'], ['مكافأة', 'مكافأة شهرية'], ['دخل ثابت آخر', 'دخل ثابت آخر']], 'راتب شهري'), sAmt = amtInput();
    var sDay = el('input', { type: 'number', min: '1', max: '31', placeholder: '27' });
    srcCard.appendChild(el('form', { class: 'form', onsubmit: function (e) {
      e.preventDefault();
      var n = cleanText(sName.value), a = parseAmount(sAmt.value), d = sDay.value ? parseInt(latinDigits(sDay.value), 10) : 0;
      if (!n) return fail('src', 'اكتب اسم المصدر.');
      if (a === null) return fail('src', 'اكتب المبلغ الشهري رقمًا أكبر من صفر.');
      if (sDay.value && !(d >= 1 && d <= 31)) return fail('src', 'يوم الإيداع بين 1 و31.');
      S().sources.push({ id: uid(), name: n, kind: sKind.value, amount: a, day: d, since: ui.month });
      commit('src', 'أُضيف المصدر، ويُحسب تلقائيًا كل شهر من ' + monthName(ui.month) + '.');
    } }, field('s-name', 'المصدر', sName, true), field('s-kind', 'النوع', sKind), field('s-amt', 'المبلغ الشهري', sAmt), field('s-day', 'يوم الإيداع', sDay),
      el('button', { class: 'btn', type: 'submit' }, 'إضافة مصدر')), msgEl('src'));
    wrap.appendChild(srcCard);

    // إيرادات متغيرة
    var iCard = el('section', { class: 'card' }, sectionTitle('plus', 'إضافة إيراد متغيّر'));
    var srcOpts = [['إيراد آخر', 'إيراد آخر']].concat(S().sources.map(function (s) { return [s.name, s.name]; }));
    var iSrc = select(srcOpts, 'إيراد آخر'), iAmt = amtInput(), iDate = dateInput(ui.month === mkey(today()) ? today() : ui.month + '-01'), iNote = txtInput('مثال: مكافأة تقديم دورة');
    iCard.appendChild(el('form', { class: 'form', onsubmit: function (e) {
      e.preventDefault();
      var a = parseAmount(iAmt.value);
      if (a === null) return fail('inc', 'اكتب المبلغ رقمًا أكبر من صفر.');
      if (!validDate(iDate.value)) return fail('inc', 'اختر تاريخًا صحيحًا.');
      S().incomes.push({ id: uid(), date: iDate.value, source: cleanText(iSrc.value), amount: a, note: cleanText(iNote.value) });
      ui.month = mkey(iDate.value);
      commit('inc', 'أُضيف الإيراد إلى ' + monthName(ui.month) + '.');
    } }, field('i-src', 'المصدر', iSrc), field('i-amt', 'المبلغ (ر.س)', iAmt), field('i-date', 'التاريخ', iDate), field('i-note', 'ملاحظة', iNote, true),
      el('button', { class: 'btn', type: 'submit' }, 'إضافة')), msgEl('inc'));
    var list = S().incomes.filter(function (x) { return mkey(x.date) === k; }).sort(function (a, b) { return b.date < a.date ? -1 : 1; });
    iCard.appendChild(el('h3', { css: { 'font-size': '15px' } }, 'إيرادات ' + monthName(k)));
    iCard.appendChild(list.length ? el('div', { class: 'list' }, list.map(function (x) {
      return el('div', { class: 'list-item' }, el('span', null, dShort(x.date) + ' · ' + x.source + (x.note ? ' — ' + x.note : '')),
        el('span', { class: 'row', css: { 'align-items': 'center', gap: '10px' } }, el('strong', { class: 'num c-green' }, '+ ' + fmt(x.amount)),
          delBtn('inc-' + x.id, 'الإيراد', function () { S().incomes = S().incomes.filter(function (y) { return y !== x; }); })));
    })) : emptyOf('inbox', 'لا توجد إيرادات متغيّرة في هذا الشهر.'));
    wrap.appendChild(iCard);
    return wrap;
  }
  function nextPay(day) {
    var now = new Date(), y = now.getFullYear(), m = now.getMonth();
    if (day < now.getDate()) { m += 1; if (m > 11) { m = 0; y += 1; } }
    return Math.min(day, new Date(y, m + 1, 0).getDate()) + ' ' + MONTHS[m];
  }

  // ---------- المصروفات
  function viewExp() {
    var k = ui.month;
    var wrap = el('div', { class: 'stack' });
    var spent = personalOf(k), av = catAverages(k);
    var excluded = sum(S().entities, function (e) { return sum(e.moves.filter(function (m) { return m.dir === 'out' && mkey(m.date) === k; }), function (m) { return m.amount; }); });
    var dd = av.total ? Math.round((spent - av.total) / av.total * 100) : null;
    wrap.appendChild(el('div', { class: 'grid' },
      stat('إجمالي مصروف ' + monthShort(k), fmt(spent), null, { hero: true }),
      stat(av.total ? 'مقارنة بمتوسطك (' + fmt(av.total) + ')' : 'مقارنة بمتوسطك', dd === null ? '—' : (dd > 0 ? '+' : '') + dd + '%', null, { unit: false }),
      stat('مستبعد من التحليل (عهد وأمانات)', fmt(excluded), null, { color: 'c-brass' })));

    // إضافة مصروف
    var eDate = dateInput(k === mkey(today()) ? today() : k + '-01'), eDesc = txtInput('مثال: بقالة، غداء، صيانة');
    var eCat = select(CATS.map(function (c) { return [c, c]; }), CATS[0]);
    var entOpts = [['p', 'شخصي']].concat(S().entities.filter(function (e) { return !e.closed; }).map(function (e) { return ['e:' + e.id, (e.type === 'c' ? 'عهدة — ' : 'أمانة — ') + e.name]; }));
    var eKind = select(entOpts, 'p'), eAmt = amtInput();
    eKind.addEventListener('change', function () { eCat.disabled = eKind.value !== 'p'; });
    var card = el('section', { class: 'card' }, sectionTitle('plus', 'إضافة مصروف'),
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault();
        var d = cleanText(eDesc.value), a = parseAmount(eAmt.value);
        if (!validDate(eDate.value)) return fail('exp', 'اختر تاريخًا صحيحًا.');
        if (!d) return fail('exp', 'اكتب وصف المصروف.');
        if (a === null) return fail('exp', 'اكتب المبلغ رقمًا أكبر من صفر.');
        if (eKind.value === 'p') {
          S().expenses.push({ id: uid(), date: eDate.value, desc: d, cat: eCat.value, amount: a });
        } else {
          var ent = findEnt(eKind.value.slice(2));
          if (!ent) return fail('exp', 'اختر الجهة من القائمة.');
          if (a > entBal(ent) + 0.001) return fail('exp', 'المبلغ أكبر من المتبقي في «' + ent.name + '» (' + fmt(entBal(ent)) + ' ر.س).');
          ent.moves.push({ id: uid(), date: eDate.value, dir: 'out', amount: a, desc: d });
        }
        ui.month = mkey(eDate.value);
        commit('exp', 'أُضيف إلى مصروفات ' + monthName(ui.month) + '.');
      } }, field('e-date', 'التاريخ', eDate), field('e-desc', 'الوصف', eDesc, true), field('e-kind', 'النوع', eKind), field('e-cat', 'التصنيف', eCat), field('e-amt', 'المبلغ (ر.س)', eAmt),
        el('button', { class: 'btn', type: 'submit' }, 'إضافة')), msgEl('exp'));
    wrap.appendChild(card);

    // التقسيم
    var t = catTotals(k);
    var cats = el('section', { class: 'card' }, sectionTitle('dash', 'التقسيم حسب نوع المصروف'));
    var any = false;
    CATS.slice().sort(function (a, b) { return t[b] - t[a]; }).forEach(function (c) {
      if (!t[c] && !av.avg[c]) return; any = true;
      var d = av.avg[c] ? Math.round((t[c] - av.avg[c]) / av.avg[c] * 100) : null;
      var over = d !== null && d >= 10;
      cats.appendChild(el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '6px' } },
        el('div', { class: 'card-head', css: { 'font-size': '14px' } }, el('span', { css: { 'font-weight': '600' } }, c),
          el('span', { class: 'row', css: { gap: '12px', 'align-items': 'center' } },
            d === null ? null : el('span', { class: 'pill ' + (over ? 'warn' : 'ok') }, d > 0 ? 'أعلى من متوسطك ' + d + '%' : d < 0 ? 'أقل من متوسطك ' + (-d) + '%' : 'ضمن المتوسط'),
            el('strong', { class: 'num' }, fmt(t[c]) + ' ر.س'),
            el('span', { class: 'num', css: { color: 'var(--muted)', 'min-width': '38px', 'text-align': 'left' } }, (spent ? Math.round(t[c] / spent * 100) : 0) + '%'))),
        bar(spent ? t[c] / spent * 100 : 0, over ? 'brass' : 'navy')));
    });
    if (!any) cats.appendChild(emptyOf('inbox', 'لا توجد مصروفات في هذا الشهر.'));
    wrap.appendChild(cats);

    // العمليات
    var rows = S().expenses.filter(function (x) { return mkey(x.date) === k; }).map(function (x) { return { x: x, kind: 'p', cat: x.cat, del: function () { S().expenses = S().expenses.filter(function (y) { return y !== x; }); } }; });
    S().entities.forEach(function (e) { e.moves.forEach(function (m) { if (mkey(m.date) === k) rows.push({ x: { id: m.id, date: m.date, desc: m.desc || (m.dir === 'in' ? 'استلام' : 'صرف'), amount: m.amount, dir: m.dir }, kind: e.type, cat: e.name, del: function () { e.moves = e.moves.filter(function (y) { return y !== m; }); } }); }); });
    S().incomes.forEach(function (x) { if (mkey(x.date) === k) rows.push({ x: { id: x.id, date: x.date, desc: x.source + (x.note ? ' — ' + x.note : ''), amount: x.amount, dir: 'in' }, kind: 'in', cat: 'إيراد', del: function () { S().incomes = S().incomes.filter(function (y) { return y !== x; }); } }); });
    rows.sort(function (a, b) { return a.x.date < b.x.date ? 1 : -1; });
    var tbody = el('tbody');
    rows.slice(0, 300).forEach(function (r) {
      tbody.appendChild(el('tr', null, el('td', { class: 'num', css: { color: 'var(--muted)' } }, dShort(r.x.date)), el('td', null, r.x.desc),
        el('td', { css: { color: 'var(--muted)' } }, r.cat), el('td', null, kindPill(r.kind)),
        el('td', { class: 'amt' }, (r.x.dir === 'in' ? '+ ' : '') + fmt(r.x.amount)),
        el('td', null, delBtn('row-' + r.x.id, r.x.desc, r.del))));
    });
    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('exp', 'عمليات ' + monthName(k)),
      rows.length ? el('div', { class: 'table-wrap' }, el('table', null,
        el('thead', null, el('tr', null, el('th', null, 'التاريخ'), el('th', null, 'الوصف'), el('th', null, 'التصنيف'), el('th', null, 'النوع'), el('th', { class: 'amt' }, 'المبلغ'), el('th', null, el('span', { class: 'sr' }, 'إجراء')))),
        tbody)) : emptyOf('inbox', 'لا توجد عمليات في هذا الشهر. أضف مصروفًا أو استورد كشف الحساب.')));
    return wrap;
  }
  function findEnt(id) { return S().entities.filter(function (e) { return e.id === id; })[0]; }

  // ---------- الديون
  function viewDebts() {
    var on = S().debts.filter(function (d) { return d.dir === 'on'; });
    var tot = sum(on, function (d) { return d.total; }), paid = sum(on, debtPaid);
    var wrap = el('div', { class: 'stack' });
    wrap.appendChild(el('div', { class: 'grid' },
      stat('إجمالي الديون', fmt(tot)), stat('المسدَّد', fmt(paid), null, { color: 'c-green' }),
      stat('المتبقي', fmt(tot - paid), null, { hero: true }), stat('الأقساط الشهرية', fmt(monthlyInstallments()))));

    var dName = txtInput('مثال: تمويل شخصي'), dType = select([['on', 'دين عليّ'], ['for', 'دين لي عند غيري']], 'on');
    var dTot = amtInput(), dPaid = amtInput(), dMon = amtInput(), dEnd = el('input', { type: 'text', inputmode: 'numeric', placeholder: '2029', maxlength: '4', dir: 'ltr' });
    var add = el('section', { class: 'card', css: { flex: '3 1 420px' } }, sectionTitle('plus', 'إضافة دين'),
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault();
        var n = cleanText(dName.value), t = parseAmount(dTot.value);
        var p = dPaid.value ? parseAmount(dPaid.value, true) : 0, m = dMon.value ? parseAmount(dMon.value, true) : 0;
        var end = latinDigits(dEnd.value).trim();
        if (!n) return fail('debt', 'اكتب اسم الدين أو الشخص.');
        if (t === null) return fail('debt', 'اكتب المبلغ الكلي رقمًا أكبر من صفر.');
        if (p === null || m === null) return fail('debt', 'المسدَّد والقسط لازم يكونان أرقامًا.');
        if (p > t) return fail('debt', 'المسدَّد أكبر من المبلغ الكلي.');
        if (end && !/^20\d\d$/.test(end)) return fail('debt', 'سنة الانتهاء أربعة أرقام مثل 2029.');
        S().debts.push({ id: uid(), name: n, dir: dType.value, total: t, paid: p, monthly: m, end: end, payments: [] });
        commit('debt', dType.value === 'for' ? 'أُضيف إلى «ديون لك عند الآخرين».' : 'أُضيف الدين إلى قائمتك.');
      } }, field('d-name', 'اسم الدين أو الشخص', dName, true), field('d-type', 'النوع', dType), field('d-tot', 'المبلغ الكلي', dTot), field('d-paid', 'المسدَّد حتى الآن', dPaid), field('d-mon', 'القسط الشهري', dMon), field('d-end', 'سنة الانتهاء', dEnd),
        el('button', { class: 'btn', type: 'submit' }, 'إضافة')), msgEl('debt'));

    var open = S().debts.filter(function (d) { return debtPaid(d) < d.total; });
    var pDebt = select(open.map(function (d) { return [d.id, (d.dir === 'for' ? 'لي عند: ' : '') + d.name]; }), open[0] && open[0].id);
    var pAmt = amtInput(), pDate = dateInput();
    var pay = el('section', { class: 'card', css: { flex: '2 1 280px' } }, sectionTitle('check', 'تسجيل سداد'),
      open.length ? el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault();
        var d = S().debts.filter(function (x) { return x.id === pDebt.value; })[0], a = parseAmount(pAmt.value);
        if (!d) return fail('pay', 'اختر الدين.');
        if (a === null) return fail('pay', 'اكتب مبلغ السداد رقمًا أكبر من صفر.');
        if (!validDate(pDate.value)) return fail('pay', 'اختر تاريخًا صحيحًا.');
        var rem = d.total - debtPaid(d);
        if (a > rem + 0.001) return fail('pay', 'المبلغ أكبر من المتبقي (' + fmt(rem) + ' ر.س).');
        d.payments.push({ id: uid(), date: pDate.value, amount: a });
        commit('pay', 'سُجّل سداد ' + fmt(a) + ' ر.س' + (debtPaid(d) >= d.total ? '، واكتمل سداد الدين.' : '.'));
      } }, field('p-debt', 'الدين', pDebt, true), field('p-amt', 'مبلغ السداد', pAmt), field('p-date', 'التاريخ', pDate), el('button', { class: 'btn dark', type: 'submit' }, 'تسجيل'))
        : emptyOf('inbox', 'لا توجد ديون مفتوحة.'),
      el('span', { css: { 'font-size': '12px', color: 'var(--muted)' } }, 'الدين اللي يكتمل سداده ينتقل تلقائيًا إلى «ديون أنجزتها».'), msgEl('pay'));
    wrap.appendChild(el('div', { class: 'row' }, add, pay));

    var act = activeDebts('on');
    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('debts', 'ديون قائمة عليك'),
      act.length ? act.map(function (d) {
        var p = debtPaid(d), pct = p / d.total * 100;
        return el('div', { css: { display: 'flex', 'flex-direction': 'column', gap: '8px', 'padding-bottom': '14px', 'border-bottom': '1px solid var(--line)' } },
          el('div', { class: 'card-head' }, el('strong', null, d.name), el('span', { class: 'meta num', css: { 'font-size': '13px' } }, 'قسط ' + fmt(d.monthly) + ' ر.س شهريًا' + (d.end ? ' · ينتهي ' + d.end : ''))),
          bar(pct),
          el('div', { class: 'card-head', css: { 'font-size': '13px' } }, el('span', { class: 'num' }, 'مسدَّد ' + fmt(p) + ' من ' + fmt(d.total) + ' (' + Math.round(pct) + '%)'),
            el('span', { class: 'row', css: { gap: '10px', 'align-items': 'center' } }, el('strong', { class: 'num' }, 'المتبقي ' + fmt(d.total - p) + ' ر.س'),
              delBtn('debt-' + d.id, d.name, function () { S().debts = S().debts.filter(function (y) { return y !== d; }); }))));
      }) : emptyOf('inbox', 'لا توجد ديون قائمة.')));

    var done = S().debts.filter(function (d) { return d.dir === 'on' && debtPaid(d) >= d.total; });
    var owed = S().debts.filter(function (d) { return d.dir === 'for'; });
    wrap.appendChild(el('div', { class: 'row' },
      el('section', { class: 'card', css: { flex: '1 1 300px' } }, sectionTitle('check', 'ديون أنجزتها'),
        done.length ? el('div', { class: 'list' }, done.map(function (d) {
          var last = d.payments.slice().sort(function (a, b) { return a.date < b.date ? 1 : -1; })[0];
          return el('div', { class: 'list-item' }, el('span', null, d.name), el('span', { class: 'c-green num', css: { 'font-weight': '600' } }, fmt(d.total) + ' ر.س — سُدِّد بالكامل' + (last ? ' في ' + monthName(mkey(last.date)) : '')));
        })) : emptyOf('inbox', 'لم تكمل سداد أي دين بعد.')),
      el('section', { class: 'card', css: { flex: '1 1 300px' } }, sectionTitle('user', 'ديون لك عند الآخرين'),
        owed.length ? el('div', { class: 'list' }, owed.map(function (d) {
          var r = d.total - debtPaid(d);
          return el('div', { class: 'list-item' }, el('span', null, d.name), el('span', { class: 'row', css: { gap: '10px', 'align-items': 'center' } },
            el('strong', { class: 'num' }, r > 0 ? fmt(r) + ' ر.س' : 'استُرد بالكامل'),
            delBtn('owed-' + d.id, d.name, function () { S().debts = S().debts.filter(function (y) { return y !== d; }); })));
        })) : emptyOf('inbox', 'لا يوجد أحد مدين لك.'))));
    return wrap;
  }

  // ---------- العهد والأمانات (نفس البنية)
  function viewCustody() { return viewEntities('c'); }
  function viewAmanat() { return viewEntities('a'); }
  function viewEntities(type) {
    var isC = type === 'c', key = 'ent' + type;
    var wrap = el('div', { class: 'stack' });
    wrap.appendChild(el('div', { class: 'note' }, icon('info'), isC
      ? 'مبالغ العهد تُستبعد تلقائيًا من تحليل مصروفك الشخصي، وتظهر هنا حتى تصفّيها مع جهتها.'
      : 'الأمانات مبالغ محفوظة عندك لغيرك، تُفصل عن مصروفك وعن العهد، وتعرف بالضبط كم عندك لكل جهة.'));

    var list = ents(type);
    var sel = select(list.map(function (e) { return [e.id, e.name]; }).concat([['new', isC ? '+ عهدة جديدة' : '+ جهة جديدة']]), list[0] ? list[0].id : 'new');
    var nName = txtInput(isC ? 'مثال: جمعية التحفيظ' : 'مثال: حلقة الحي');
    var nWrap = field(key + '-new', isC ? 'اسم العهدة الجديدة' : 'اسم الجهة الجديدة', nName);
    nWrap.hidden = sel.value !== 'new';
    sel.addEventListener('change', function () { nWrap.hidden = sel.value !== 'new'; });
    var dir = select([['in', 'استلمت مبلغ'], ['out', isC ? 'صرفت من العهدة' : 'سلّمت أو صرفت']], 'in');
    var amt = amtInput(), date = dateInput(), desc = txtInput(isC ? 'مثال: مستلزمات حلقات' : 'مثال: من متبرع لكتب المسجد');
    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('plus', isC ? 'تسجيل حركة عهدة' : 'تسجيل حركة أمانة'),
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault();
        var a = parseAmount(amt.value);
        if (a === null) return fail(key, 'اكتب المبلغ رقمًا أكبر من صفر.');
        if (!validDate(date.value)) return fail(key, 'اختر تاريخًا صحيحًا.');
        var ent;
        if (sel.value === 'new') {
          var n = cleanText(nName.value);
          if (!n) return fail(key, 'اكتب اسم الجهة.');
          if (dir.value === 'out') return fail(key, 'ابدأ بتسجيل المبلغ المستلم لهذه الجهة أولًا.');
          ent = { id: uid(), type: type, name: n, closed: false, deadline: '', moves: [] };
          S().entities.push(ent);
        } else {
          ent = findEnt(sel.value);
          if (!ent) return fail(key, 'اختر الجهة.');
          if (dir.value === 'out' && a > entBal(ent) + 0.001) return fail(key, 'المبلغ أكبر من المحفوظ عندك لهذه الجهة (' + fmt(entBal(ent)) + ' ر.س).');
          if (ent.closed && dir.value === 'in') ent.closed = false;
        }
        ent.moves.push({ id: uid(), date: date.value, dir: dir.value, amount: a, desc: cleanText(desc.value) });
        commit(key, 'سُجّلت الحركة في «' + ent.name + '».');
      } }, field(key + '-sel', 'الجهة', sel), nWrap, field(key + '-dir', 'الحركة', dir), field(key + '-amt', 'المبلغ (ر.س)', amt), field(key + '-date', 'التاريخ', date), field(key + '-desc', 'الوصف', desc, true),
        el('button', { class: 'btn', type: 'submit' }, 'تسجيل')), msgEl(key)));

    if (!list.length) { wrap.appendChild(emptyOf('inbox', isC ? 'لا توجد عهد بعد. سجّل أول مبلغ استلمته.' : 'لا توجد أمانات بعد.')); return wrap; }
    wrap.appendChild(el('div', { class: 'grid', css: { 'grid-template-columns': 'repeat(auto-fit, minmax(270px, 1fr))' } }, list.map(function (e) {
      var i = entIn(e), o = entOut(e), b = i - o;
      var log = e.moves.slice().sort(function (a, b2) { return a.date < b2.date ? 1 : -1; }).slice(0, 5);
      var card = el('section', { class: 'card ent-card ' + type },
        el('div', { class: 'card-head' }, el('h2', { css: { 'font-size': '17px' } }, e.name),
          isC ? el('span', { class: 'pill ' + (e.closed ? 'a' : 'c') }, e.closed ? 'مصفّاة' : 'مفتوحة') : null));
      if (isC) {
        card.appendChild(el('div', { class: 'kv' },
          el('div', null, el('span', null, 'المستلم'), el('strong', null, fmt(i))),
          el('div', null, el('span', null, 'المصروف'), el('strong', null, fmt(o))),
          el('div', null, el('span', null, 'المتبقي'), el('strong', { class: 'c-brass' }, fmt(b)))));
        card.appendChild(bar(i ? o / i * 100 : 0, 'brass'));
      } else {
        card.appendChild(el('div', { css: { display: 'flex', 'align-items': 'baseline', gap: '8px' } }, el('span', { class: 'big-num c-green' }, fmt(b)), el('span', { css: { 'font-size': '14px', color: 'var(--muted)' } }, 'ر.س محفوظة عندك الآن')));
        card.appendChild(el('div', { class: 'card-head num', css: { 'font-size': '14px', color: 'var(--ink-2)' } }, el('span', null, 'استلمت ' + fmt(i)), el('span', null, 'سلّمت ' + fmt(o))));
      }
      card.appendChild(el('div', { class: 'log' }, log.map(function (m) {
        return el('span', null, el('span', null, dShort(m.date) + ' · ' + (m.dir === 'in' ? 'استلام' : (isC ? 'صرف' : 'تسليم')) + (m.desc ? ' — ' + m.desc : '')), el('b', { class: m.dir === 'in' ? 'in' : '' }, (m.dir === 'in' ? '+ ' : '− ') + fmt(m.amount)));
      })));
      card.appendChild(el('div', { class: 'row', css: { gap: '8px' } },
        isC ? el('button', { type: 'button', class: 'btn ghost small', onclick: function () {
          if (!e.closed && b > 0.001) { toast('صفِّ المتبقي (' + fmt(b) + ' ر.س) بتسجيل صرف أو تسليم قبل إغلاق العهدة.'); return; }
          e.closed = !e.closed; persist(); render();
        } }, e.closed ? 'إعادة فتح' : 'تصفية وإغلاق') : null,
        delBtn('ent-' + e.id, e.name, function () { S().entities = S().entities.filter(function (y) { return y !== e; }); })));
      return card;
    })));
    return wrap;
  }

  // ---------- استيراد كشف الحساب (CSV) — يُقرأ محليًا فقط
  function viewUpload() {
    var wrap = el('div', { class: 'stack' });
    wrap.appendChild(el('div', { class: 'steps' },
      el('div', null, 'صدّر الكشف بصيغة CSV'), el('div', null, 'تصنيف تلقائي للعمليات'),
      el('div', null, 'راجع: شخصي / عهدة / أمانة'), el('div', null, 'اعتمد وحلّل الشهر')));

    var input = el('input', { id: 'csv', type: 'file', accept: '.csv,text/csv,.txt', class: 'sr' });
    var drop = el('label', { for: 'csv', class: 'drop' }, el('span', { class: 'big' }, icon('upload')),
      el('strong', { css: { 'font-size': '16px' } }, 'اسحب ملف الكشف هنا أو اضغط للاختيار'),
      el('span', { css: { 'font-size': '13px', color: 'var(--muted)' } }, 'ملف CSV حتى 2 ميجابايت. يُقرأ داخل متصفحك ولا يُرفع لأي مكان.'),
      el('span', { css: { 'font-size': '12px', color: 'var(--muted)' } }, 'كشف PDF أو Excel؟ افتحه في Excel أو Numbers واحفظه بصيغة CSV.'), input);
    var handle = function (file) {
      if (!file) return;
      if (file.size > MAX_CSV_BYTES) return fail('csv', 'الملف أكبر من 2 ميجابايت.');
      if (!/\.(csv|txt)$/i.test(file.name)) return fail('csv', 'اختر ملفًا بصيغة CSV.');
      file.arrayBuffer().then(function (buf) {
        var text = new TextDecoder('utf-8').decode(buf);
        if ((text.match(/\uFFFD/g) || []).length > 5) { try { text = new TextDecoder('windows-1256').decode(buf); } catch (e) { /* keep utf-8 */ } }
        var rows = parseStatement(text);
        if (!rows.length) return fail('csv', 'ما قدرنا نقرأ عمليات من الملف. تأكد أن فيه أعمدة التاريخ والوصف والمبلغ (أو مدين/دائن).');
        ui.review = rows; say('csv', true, 'قُرئت ' + rows.length + ' عملية. راجع التصنيف ثم اعتمد.'); render();
      }).catch(function () { fail('csv', 'تعذّرت قراءة الملف.'); });
    };
    input.addEventListener('change', function () { handle(input.files[0]); input.value = ''; });
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); handle(e.dataTransfer.files[0]); });
    wrap.appendChild(el('section', { class: 'card' }, drop, msgEl('csv')));

    if (ui.review && ui.review.length) {
      var opts = function (r) {
        var o = r.dir === 'out' ? CATS.map(function (c) { return ['p:' + c, 'شخصي — ' + c]; }) : [['in', 'دخل']];
        S().entities.filter(function (e) { return !e.closed || r.dir === 'in'; }).forEach(function (e) { o.push(['e:' + e.id, (e.type === 'c' ? 'عهدة — ' : 'أمانة — ') + e.name]); });
        o.push(['skip', 'تجاهل']);
        return o;
      };
      var tbody = el('tbody');
      ui.review.forEach(function (r, i) {
        var s = select(opts(r), r.choice); s.id = 'rv-' + i;
        s.addEventListener('change', function () { r.choice = s.value; });
        tbody.appendChild(el('tr', null, el('td', { class: 'num' }, dShort(r.date)), el('td', null, r.desc),
          el('td', { class: 'amt ' + (r.dir === 'in' ? 'c-green' : '') }, (r.dir === 'in' ? '+ ' : '') + fmt(r.amount)),
          el('td', null, el('label', { for: s.id, class: 'sr' }, 'نوع العملية'), s)));
      });
      wrap.appendChild(el('section', { class: 'card' }, sectionTitle('file', 'مراجعة العمليات قبل الاعتماد'),
        el('span', { css: { 'font-size': '13px', color: 'var(--muted)' } }, 'التطبيق يقترح النوع، وأنت تعدّل اللي يحتاج. العمليات المكررة (نفس التاريخ والوصف والمبلغ) تُتجاهل تلقائيًا.'),
        el('div', { class: 'table-wrap' }, el('table', null, el('thead', null, el('tr', null, el('th', null, 'التاريخ'), el('th', null, 'الوصف'), el('th', { class: 'amt' }, 'المبلغ'), el('th', null, 'النوع'))), tbody)),
        el('div', { class: 'row' },
          el('button', { type: 'button', class: 'btn', onclick: approve }, icon('check'), 'اعتماد وتحليل الشهر'),
          el('button', { type: 'button', class: 'btn ghost', onclick: function () { ui.review = null; ui.msgs = {}; render(); } }, 'إلغاء'))));
    }
    return wrap;
  }

  function approve() {
    var added = 0, skipped = 0, lastMonth = null;
    var seen = {};
    S().expenses.forEach(function (x) { seen['p|' + x.date + '|' + x.desc + '|' + x.amount] = 1; });
    S().incomes.forEach(function (x) { seen['in|' + x.date + '|' + x.note + '|' + x.amount] = 1; });
    S().entities.forEach(function (e) { e.moves.forEach(function (m) { seen['e|' + m.date + '|' + m.desc + '|' + m.amount] = 1; }); });
    ui.review.forEach(function (r) {
      var c = r.choice;
      if (c === 'skip') { skipped++; return; }
      if (c.slice(0, 2) === 'p:' && r.dir === 'out') {
        var key = 'p|' + r.date + '|' + r.desc + '|' + r.amount; if (seen[key]) { skipped++; return; } seen[key] = 1;
        S().expenses.push({ id: uid(), date: r.date, desc: r.desc, cat: CATS.indexOf(c.slice(2)) >= 0 ? c.slice(2) : 'أخرى', amount: r.amount });
      } else if (c === 'in' && r.dir === 'in') {
        var k2 = 'in|' + r.date + '|' + r.desc + '|' + r.amount; if (seen[k2]) { skipped++; return; } seen[k2] = 1;
        S().incomes.push({ id: uid(), date: r.date, source: 'من كشف الحساب', amount: r.amount, note: r.desc });
      } else if (c.slice(0, 2) === 'e:') {
        var ent = findEnt(c.slice(2)); if (!ent) { skipped++; return; }
        var k3 = 'e|' + r.date + '|' + r.desc + '|' + r.amount; if (seen[k3]) { skipped++; return; } seen[k3] = 1;
        ent.moves.push({ id: uid(), date: r.date, dir: r.dir, amount: r.amount, desc: r.desc });
      } else { skipped++; return; }
      added++; if (!lastMonth || mkey(r.date) > lastMonth) lastMonth = mkey(r.date);
    });
    ui.review = null;
    if (lastMonth) ui.month = lastMonth;
    ui.tab = 'exp';
    commit('exp', 'اعتُمدت ' + added + ' عملية' + (skipped ? '، وتُجوهلت ' + skipped : '') + '.');
  }

  // قارئ CSV بسيط يدعم علامات التنصيص والفاصلة أو الفاصلة المنقوطة
  function parseCSV(text) {
    text = text.replace(/^﻿/, '');
    var first = text.split(/\r?\n/, 1)[0] || '';
    var sep = (first.match(/;/g) || []).length > (first.match(/,/g) || []).length ? ';' : (first.indexOf('\t') >= 0 && first.indexOf(',') < 0 ? '\t' : ',');
    var rows = [], row = [], cell = '', q = false;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (q) {
        if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += ch;
      } else if (ch === '"') q = true;
      else if (ch === sep) { row.push(cell); cell = ''; }
      else if (ch === '\n' || ch === '\r') {
        if (ch === '\r' && text[i + 1] === '\n') i++;
        row.push(cell); cell = ''; rows.push(row); row = [];
        if (rows.length > MAX_CSV_ROWS + 20) break;
      } else cell += ch;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows;
  }
  function normDate(s) {
    s = latinDigits(s).trim().replace(/\s.*$/, '');
    var m;
    if ((m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/))) return pad(m[1], m[2], m[3]);
    if ((m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/))) return pad(m[3], m[2], m[1]);
    return null;
    function pad(y, mo, d) { var r = y + '-' + String(mo).padStart(2, '0') + '-' + String(d).padStart(2, '0'); return validDate(r) ? r : null; }
  }
  function numCell(s) {
    var t = latinDigits(s || '').replace(/[\s,٬]|SAR|ر\.?س/gi, '').replace('٫', '.');
    var neg = /^\(.*\)$/.test(t) || /^-/.test(t) || /-$/.test(t);
    t = t.replace(/[()\-+]/g, '');
    if (!/^\d+(\.\d+)?$/.test(t)) return null;
    var n = Math.round(Number(t) * 100) / 100;
    if (!isFinite(n) || n > MAX_AMOUNT) return null;
    return neg ? -n : n;
  }
  function parseStatement(text) {
    var rows = parseCSV(text).filter(function (r) { return r.some(function (c) { return c.trim(); }); });
    if (rows.length < 2) return [];
    var find = function (h, words) { for (var i = 0; i < h.length; i++) { var c = h[i].toLowerCase(); if (words.some(function (w) { return c.indexOf(w) >= 0; })) return i; } return -1; };
    var hi = -1, h;
    for (var r = 0; r < Math.min(rows.length, 15); r++) {
      h = rows[r].map(function (c) { return cleanText(c, 60); });
      if (find(h, ['تاريخ', 'date']) >= 0 && (find(h, ['مبلغ', 'amount', 'مدين', 'debit', 'دائن', 'credit', 'سحب', 'إيداع', 'ايداع']) >= 0)) { hi = r; break; }
    }
    if (hi < 0) return [];
    h = rows[hi].map(function (c) { return cleanText(c, 60); });
    var cDate = find(h, ['تاريخ', 'date']);
    var cDesc = find(h, ['وصف', 'تفاصيل', 'البيان', 'description', 'details', 'narrative', 'merchant']);
    var cDebit = find(h, ['مدين', 'debit', 'سحب', 'withdraw']);
    var cCredit = find(h, ['دائن', 'credit', 'إيداع', 'ايداع', 'deposit']);
    var cAmt = find(h, ['مبلغ', 'amount']);
    var out = [];
    rows.slice(hi + 1, hi + 1 + MAX_CSV_ROWS).forEach(function (row) {
      var date = normDate(row[cDate] || ''); if (!date) return;
      var desc = cleanText(cDesc >= 0 ? row[cDesc] : '') || 'عملية بدون وصف';
      var amount = null, dir = null;
      if (cDebit >= 0 || cCredit >= 0) {
        var dv = cDebit >= 0 ? numCell(row[cDebit]) : null, cv = cCredit >= 0 ? numCell(row[cCredit]) : null;
        if (dv) { amount = Math.abs(dv); dir = 'out'; } else if (cv) { amount = Math.abs(cv); dir = 'in'; }
      }
      if (amount === null && cAmt >= 0) { var v = numCell(row[cAmt]); if (v) { amount = Math.abs(v); dir = v < 0 ? 'out' : 'in'; } }
      if (!amount) return;
      out.push({ date: date, desc: desc, amount: amount, dir: dir, choice: suggest(desc, dir) });
    });
    return out;
  }
  function suggest(desc, dir) {
    var d = desc.toLowerCase();
    var hit = S().entities.filter(function (e) { return d.indexOf(e.name.toLowerCase().replace(/^(أمانة|عهدة)\s+/, '')) >= 0; })[0];
    if (hit && (dir === 'in' || !hit.closed)) return 'e:' + hit.id;
    if (dir === 'in') return 'in';
    for (var i = 0; i < CAT_WORDS.length; i++) if (CAT_WORDS[i][1].some(function (w) { return d.indexOf(w) >= 0; })) return 'p:' + CAT_WORDS[i][0];
    return 'p:أخرى';
  }

  // ---------- الإعدادات والأمان
  function viewSettings() {
    var wrap = el('div', { class: 'stack' });
    var p = S().profile;

    var name = txtInput('اختياري، يظهر في الشريط الجانبي فقط', 60); name.value = p.name;
    var lockSel = select([['1', 'دقيقة'], ['2', 'دقيقتين'], ['5', '5 دقائق'], ['10', '10 دقائق'], ['15', '15 دقيقة'], ['30', '30 دقيقة']], String(p.lockMinutes));
    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('user', 'الملف الشخصي'),
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault(); p.name = cleanText(name.value, 60); p.lockMinutes = +lockSel.value; bumpIdle(); commit('prof', 'حُفظت الإعدادات.');
      } }, field('set-name', 'الاسم الظاهر', name, true), field('set-lock', 'القفل التلقائي بعد', lockSel), el('button', { class: 'btn dark', type: 'submit' }, 'حفظ')), msgEl('prof')));

    // بيانات الدخول
    var cur = pwField('cr-cur', 'كلمة المرور الحالية', 'current-password');
    var nu = el('input', { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', maxlength: '32', dir: 'ltr', value: session.user || '' });
    var n1 = pwField('cr-n1', 'كلمة المرور الجديدة', 'new-password', '10 أحرف على الأقل، فيها حروف وأرقام.');
    var n2 = pwField('cr-n2', 'تأكيد كلمة المرور الجديدة', 'new-password');
    var credBtn = el('button', { class: 'btn dark', type: 'submit' }, icon('key'), 'تحديث بيانات الدخول');
    wrap.appendChild(el('section', { class: 'card' }, el('div', { class: 'card-head' }, sectionTitle('key', 'بيانات الدخول'), el('span', { class: 'meta', dir: 'ltr' }, session.user || '')),
      el('form', { css: { display: 'grid', gap: '14px', 'grid-template-columns': 'repeat(auto-fit, minmax(220px, 1fr))', 'align-items': 'start' }, onsubmit: function (e) {
        e.preventDefault();
        var u = normUser(nu.value), np = n1.input.value;
        var err = checkNewCreds(u, np, n2.input.value);
        if (err) return fail('cred', err);
        credBtn.disabled = true;
        var curPass = cur.input.value;
        Promise.resolve().then(function () { return openVault(storageGet(VAULT_KEY), session.user, curPass); }).then(function () {
          var salt = crypto.getRandomValues(new Uint8Array(16));
          return deriveKey(u, np, salt, KDF_ITER).then(function (key) { session.key = key; session.salt = salt; session.user = u; return persist(); });
        }).then(function () { say('cred', true, 'تحدّثت بيانات الدخول وأُعيد تشفير بياناتك.'); render(); })
          .catch(function () { fail('cred', 'كلمة المرور الحالية غير صحيحة.'); });
      } },
        cur.wrap, field('cr-user', 'اسم المستخدم', nu, false, 'حروف إنجليزية صغيرة أو أرقام أو . _ -'), n1.wrap, n2.wrap,
        el('div', { css: { 'grid-column': '1 / -1', display: 'flex', 'flex-direction': 'column', gap: '10px' } }, strengthMeter(n1.input, nu), el('div', null, credBtn))), msgEl('cred')));

    // النسخ الاحتياطي
    var backup = el('section', { class: 'card' }, sectionTitle('file', 'النسخ الاحتياطي'),
      el('p', { css: { margin: '0', 'font-size': '14px', color: 'var(--ink-2)' } }, 'بياناتك محفوظة في هذا المتصفح فقط. لو مسحت بيانات المتصفح أو غيّرت الجهاز تضيع، فاحفظ نسخة احتياطية مشفّرة بين فترة وأخرى. النسخة ما تنفتح إلا باسم المستخدم وكلمة المرور.'));
    backup.appendChild(el('div', { class: 'row' },
      el('button', { type: 'button', class: 'btn', onclick: function () {
        saving.then(function () {
          var text = storageGet(VAULT_KEY) || '';
          ui.backupText = text;
          try {
            var a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/json' })), download: 'masroufi-backup-' + today() + '.json' });
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
          } catch (e) { /* التنزيل غير متاح: يبقى النص للنسخ */ }
          say('bk', true, 'جُهّزت النسخة. إذا ما بدأ التنزيل، انسخ النص تحت واحفظه في ملف.'); render();
        });
      } }, icon('file'), 'تنزيل نسخة مشفّرة')));
    if (ui.backupText) {
      var ta = el('textarea', { readonly: true, rows: '4' }); ta.value = ui.backupText;
      backup.appendChild(field('bk-text', 'نص النسخة المشفّرة', ta, true));
      backup.appendChild(el('div', null, el('button', { type: 'button', class: 'btn ghost small', onclick: function () {
        if (navigator.clipboard) navigator.clipboard.writeText(ui.backupText).then(function () { toast('نُسخ النص.'); }, function () { ta.select(); });
        else ta.select();
      } }, 'نسخ النص')));
    }
    backup.appendChild(msgEl('bk'));

    var rFile = el('input', { type: 'file', accept: '.json,application/json' });
    var rUser = el('input', { type: 'text', autocomplete: 'off', autocapitalize: 'none', maxlength: '32', dir: 'ltr' });
    var rPass = el('input', { type: 'password', autocomplete: 'off', maxlength: '128', dir: 'ltr' });
    backup.appendChild(composer('upload', 'استعادة نسخة',
      el('form', { class: 'form', onsubmit: function (e) {
        e.preventDefault();
        var f = rFile.files[0];
        if (!f) return fail('rs', 'اختر ملف النسخة.');
        if (f.size > MAX_BACKUP_BYTES) return fail('rs', 'الملف كبير جدًا.');
        f.text().then(function (text) { return openVault(text, rUser.value, rPass.value); }).then(function (r) {
          r.state.setup = false;
          session.state = r.state; rPass.value = '';
          commit('rs', 'استُعيدت النسخة، وصارت مشفّرة ببيانات دخولك الحالية.');
        }).catch(function () { fail('rs', 'تعذّر فتح النسخة: الملف غير صالح، أو اسم المستخدم أو كلمة المرور غير صحيحة.'); });
      } }, field('rs-file', 'ملف النسخة', rFile, true), field('rs-user', 'اسم مستخدم النسخة', rUser), field('rs-pass', 'كلمة مرور النسخة', rPass),
        el('button', { class: 'btn ghost', type: 'submit' }, 'استعادة')),
      el('span', { class: 'hint', css: { 'font-size': '12px', color: 'var(--muted)' } }, 'الاستعادة تستبدل كل البيانات الحالية.'), msgEl('rs')));
    wrap.appendChild(backup);

    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('amanat', 'كيف نحمي بياناتك'),
      el('div', { class: 'sec-list' }, [
        ['lock', 'تشفير AES-256-GCM', 'كل البيانات مشفّرة قبل الحفظ، والمفتاح مشتق من اسم المستخدم وكلمة المرور بـ PBKDF2 (600,000 دورة).'],
        ['device', 'على جهازك فقط', 'ما فيه خادم ولا حساب، والمنصة ما تتصل بأي موقع خارجي.'],
        ['timer', 'قفل تلقائي', 'تُقفل بعد ' + p.lockMinutes + ' ' + (p.lockMinutes > 2 ? 'دقائق' : p.lockMinutes === 2 ? 'دقيقتين' : 'دقيقة') + ' من عدم الاستخدام، ويُمسح المفتاح من الذاكرة.'],
        ['alert', 'حماية من التخمين', 'انتظار يتضاعف بعد كل محاولة دخول خاطئة.'],
        ['upload', 'الكشوف لا تُرفع', 'ملف الكشف يُقرأ داخل المتصفح، ولا يُحفظ منه إلا العمليات اللي تعتمدها.']
      ].map(function (x) { return el('div', null, icon(x[0]), el('div', null, el('strong', null, x[1]), el('span', null, x[2]))); }))));

    wrap.appendChild(el('section', { class: 'card' }, sectionTitle('trash', 'حذف كل البيانات'), wipeBlock('set-wipe', 'حذف كل البيانات من هذا الجهاز')));
    return wrap;
  }

  // ---------------------------------------------------------------- تشغيل
  window.addEventListener('pagehide', function () { if (session.key) persist(); });
  renderLock();
})();
