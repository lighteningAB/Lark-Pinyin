<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Pinyin Helper</title>
    <style>
      body { font: 14px/1.4 system-ui, sans-serif; margin: 24px; }
      textarea { width: 100%; height: 120px; }
      .out { margin-top: 12px; padding: 12px; background:#f6f7f9; border-radius:8px; }
    </style>
    <script src="https://unpkg.com/pinyin-pro/dist/pinyin-pro.umd.js"></script>
  </head>
  <body>
    <h2>Pinyin Helper (Demo)</h2>
    <p>Type or paste Chinese below. This page is only a demo; message shortcuts reply in-thread.</p>
    <textarea id="in" placeholder="例如：我喜欢学习中文"></textarea>
    <div class="out" id="out">wǒ xǐ huān xué xí zhōng wén</div>
    <script>
      const elIn = document.getElementById('in'), elOut = document.getElementById('out');
      const urlText = new URLSearchParams(location.search).get('text') || '';
      elIn.value = urlText; // if you ever open with ?text=...
      function upd(){ elOut.textContent = window.pinyinPro.pinyin(elIn.value, { toneType: 'mark' }); }
      elIn.addEventListener('input', upd); upd();
    </script>
  </body>
</html>
