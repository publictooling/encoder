// Data & Globals
const encodesDecodes = [
    { name: 'Base64', id: 'base64' },
    { name: 'URL Encode/Decode', id: 'urlencode' },
    { name: 'Unicode', id: 'unicode' },
    { name: 'Hex', id: 'hex' },
    { name: 'HTML Entities', id: 'htmlEntities' },
    { name: 'Rot13', id: 'rot13' },
    { name: 'Caesar Cipher', id: 'caesar' },
];
const hashes = [
    { name: 'SHA-1', id: 'sha1' },
    { name: 'SHA-256', id: 'sha256' },
    { name: 'SHA-512', id: 'sha512' },
    { name: 'PBKDF2 (via WebCrypto)', id: 'pbkdf2' },
];
const sidebar = document.getElementById('sidebar');
const content = document.getElementById('content');
const categoryPicker = document.getElementById('categoryPicker');
const themePicker = document.getElementById('themePicker');
let currentCategory = localStorage.getItem('selectedCategory') || 'encoders';

function createButton(item) {
    const btn = document.createElement('button');
    btn.textContent = item.name;
    btn.dataset.id = item.id;
    btn.classList.toggle('active', 
        (currentCategory === 'encoders' && item.id === encodesDecodes[0].id) ||
        (currentCategory === 'hashes' && item.id === hashes[0].id)
    );
    btn.onclick = () => {
        [...sidebar.children].forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        showAlgorithm(item.id);
    };
    return btn;
}
function populateSidebar() {
    sidebar.innerHTML = '';
    const list = currentCategory === 'encoders' ? encodesDecodes : hashes;
    list.forEach(item => sidebar.appendChild(createButton(item)));
    showAlgorithm(list[0].id); // always show first on sidebar populate
}
function clearContent() {
    content.innerHTML = '';
}
function createLabel(text, forId) {
    const label = document.createElement('label');
    label.textContent = text;
    label.htmlFor = forId;
    return label;
}
function createTextarea(id, placeholder, readOnly=false) {
    const ta = document.createElement('textarea');
    ta.id = id;
    ta.placeholder = placeholder;
    if(readOnly) ta.readOnly = true;
    return ta;
}
// Base64
function showBase64() {
    clearContent();
    const labelEnc = createLabel('Base64 String', 'base64Input');
    const taEnc = createTextarea('base64Input', 'Enter Base64 encoded string');
    const labelDec = createLabel('Decoded String', 'decodedInput');
    const taDec = createTextarea('decodedInput', 'Enter text to encode to Base64');
    content.append(labelEnc, taEnc, labelDec, taDec);
    let last = null;
    taEnc.addEventListener('input', () => {
        if (last === 'decode') { last=null; return; }
        last = 'encode';
        try { taDec.value = decodeURIComponent(escape(atob(taEnc.value))); } catch (_) { taDec.value = ''; }
        last = null;
    });
    taDec.addEventListener('input', () => {
        if (last === 'encode') { last=null; return; }
        last = 'decode';
        try { taEnc.value = btoa(unescape(encodeURIComponent(taDec.value))); } catch (_) { taEnc.value = ''; }
        last = null;
    });
}
// URL Encode/Decode
function showUrlEncode() {
    clearContent();
    const labelEnc = createLabel('URL Encoded String', 'urlEnc');
    const taEnc = createTextarea('urlEnc', 'Enter URL encoded string');
    const labelDec = createLabel('Decoded String', 'urlDec');
    const taDec = createTextarea('urlDec', 'Enter text to URL encode');
    content.append(labelEnc, taEnc, labelDec, taDec);
    let last = null;
    taEnc.addEventListener('input', () => {
        if(last === 'decode') { last=null; return; }
        last = 'encode';
        try { taDec.value = decodeURIComponent(taEnc.value); } catch (_) { taDec.value = ''; }
        last = null;
    });
    taDec.addEventListener('input', () => {
        if(last === 'encode') { last=null; return; }
        last = 'decode';
        try { taEnc.value = encodeURIComponent(taDec.value); } catch (_) { taEnc.value = ''; }
        last = null;
    });
}
// Unicode
function showUnicode() {
    clearContent();
    const labelEnc = createLabel('Unicode Code Points (hex, space-separated)', 'unicodeHex');
    const taHex = createTextarea('unicodeHex', 'Enter hex code points (e.g. 0041 0042)');
    const labelDec = createLabel('Decoded String', 'unicodeDecoded');
    const taDec = createTextarea('unicodeDecoded', 'Text to convert to hex code points');
    content.append(labelEnc, taHex, labelDec, taDec);
    let last = null;
    taHex.addEventListener('input', () => {
        if(last === 'decode') { last=null; return; }
        last = 'encode';
        try { taDec.value = taHex.value.trim().split(/\s+/).map(h => String.fromCharCode(parseInt(h, 16))).join('');
        } catch { taDec.value = ''; }
        last = null;
    });
    taDec.addEventListener('input', () => {
        if(last === 'encode') { last=null; return; }
        last = 'decode';
        taHex.value = Array.from(taDec.value).map(c => c.charCodeAt(0).toString(16).toUpperCase().padStart(4,'0')).join(' ');
        last = null;
    });
}
// Hex
function showHex() {
    clearContent();
    const labelEnc = createLabel('Hex String', 'hexStr');
    const taHex = createTextarea('hexStr', 'Enter hex string, space-separated (e.g. 41 42 43)');
    const labelDec = createLabel('Decoded String', 'hexDecoded');
    const taDec = createTextarea('hexDecoded', 'Decoded text');
    content.append(labelEnc, taHex, labelDec, taDec);
    let last = null;
    taHex.addEventListener('input', () => {
        if(last === 'decode') { last=null; return; }
        last = 'encode';
        try { taDec.value = taHex.value.trim().split(/\s+/).map(h => String.fromCharCode(parseInt(h, 16))).join('');
        } catch { taDec.value = ''; }
        last = null;
    });
    taDec.addEventListener('input', () => {
        if(last === 'encode') { last=null; return; }
        last = 'decode';
        taHex.value = Array.from(taDec.value).map(c => c.charCodeAt(0).toString(16).toUpperCase().padStart(2,'0')).join(' ');
        last = null;
    });
}
// HTML Entities
function showHtmlEntities() {
    clearContent();
    const labelEnc = createLabel('Text', 'htmlText');
    const taText = createTextarea('htmlText','Enter text');
    const labelDec = createLabel('Encoded/Decoded', 'htmlEntities');
    const taEntities = createTextarea('htmlEntities','Encoded or decoded text');
    content.append(labelEnc, taText, labelDec, taEntities);
    let last = null;
    taText.addEventListener('input', () => {
        if(last === 'decode') { last=null; return; }
        last = 'encode';
        const encoded = taText.value
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, "'");
        taEntities.value = encoded;
        last = null;
    });
    taEntities.addEventListener('input', () => {
        if(last === 'encode') { last=null; return; }
        last = 'decode';
        const decoded = taEntities.value
            .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"').replace(/'/g, "'")
            .replace(/&amp;/g, '&');
        taText.value = decoded;
        last = null;
    });
}
// Rot13 with input and output box
function showRot13() {
    clearContent();
    const labelIn = createLabel('Input Text', 'rot13Input');
    const taIn = createTextarea('rot13Input', 'Enter text to encode/decode with ROT13');
    const labelOut = createLabel('Output Text', 'rot13Output');
    const taOut = createTextarea('rot13Output', '', true);
    content.append(labelIn, taIn, labelOut, taOut);
    taIn.addEventListener('input', () => {
        const input = taIn.value;
        const output = input.replace(/[A-Za-z]/g, c => {
            const base = (c <= 'Z') ? 65 : 97;
            return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
        taOut.value = output;
    });
}
// Caesar cipher with input and output box
function showCaesar() {
    clearContent();
    const labelIn = createLabel('Input Text', 'caesarInput');
    const taIn = createTextarea('caesarInput', 'Enter text for Caesar cipher (shift by 3)');
    const labelOut = createLabel('Output Text', 'caesarOutput');
    const taOut = createTextarea('caesarOutput', '', true);
    content.append(labelIn, taIn, labelOut, taOut);
    taIn.addEventListener('input', () => {
        const input = taIn.value;
        const output = Array.from(input).map(c => {
            const code = c.charCodeAt(0);
            if (c >= 'A' && c <= 'Z') return String.fromCharCode(((code - 65 + 3) % 26) + 65);
            if (c >= 'a' && c <= 'z') return String.fromCharCode(((code - 97 + 3) % 26) + 97);
            return c;
        }).join('');
        taOut.value = output;
    });
}
// Hashing
function showHash(type) {
    clearContent();
    const labelIn = createLabel('Input Text', 'hashInput');
    const taIn = createTextarea('hashInput', 'Enter text to hash');
    const labelOut = createLabel(type.toUpperCase() + ' Hash', 'hashOutput');
    const taOut = createTextarea('hashOutput', '', true);
    content.append(labelIn, taIn, labelOut, taOut);
    taIn.addEventListener('input', () => {
        const data = taIn.value;
        if (!data) { taOut.value = ''; return; }
        if (type === 'pbkdf2') {
            const salt = new Uint8Array(16).fill(0); // fixed for demo
            crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(data), { name: 'PBKDF2' }, false, ['deriveBits']
            ).then(key => {
                crypto.subtle.deriveBits({
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                }, key, 256).then(bits => {
                    const hashArray = Array.from(new Uint8Array(bits));
                    taOut.value = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                });
            }).catch(() => { taOut.value = ''; });
            return;
        }
        let algoName = '';
        switch (type) {
            case 'sha1': algoName = 'SHA-1'; break;
            case 'sha256': algoName = 'SHA-256'; break;
            case 'sha512': algoName = 'SHA-512'; break;
            default: taOut.value = ''; return;
        }
        crypto.subtle.digest(algoName, new TextEncoder().encode(data))
            .then(hashBuffer => {
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                taOut.value = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }).catch(() => { taOut.value = ''; });
    });
}
function showAlgorithm(id) {
    if (currentCategory === 'encoders') {
        switch(id){
            case 'base64': showBase64(); break;
            case 'urlencode': showUrlEncode(); break;
            case 'unicode': showUnicode(); break;
            case 'hex': showHex(); break;
            case 'htmlEntities': showHtmlEntities(); break;
            case 'rot13': showRot13(); break;
            case 'caesar': showCaesar(); break;
            default: content.innerHTML = 'Unavailable'; break;
        }
    } else {
        showHash(id);
    }
}
// Sidebar + state logic
function populateSidebar() {
    sidebar.innerHTML = '';
    const list = currentCategory === 'encoders' ? encodesDecodes : hashes;
    list.forEach(item => { sidebar.appendChild(createButton(item)); });
    showAlgorithm(list[0].id);
}
function initEncoders() {
    currentCategory = 'encoders';
    categoryPicker.value = 'encoders';
    localStorage.setItem('selectedCategory', 'encoders');
    populateSidebar();
}
function initHashes() {
    currentCategory = 'hashes';
    categoryPicker.value = 'hashes';
    localStorage.setItem('selectedCategory', 'hashes');
    populateSidebar();
}
categoryPicker.addEventListener('change', e => {
    if (e.target.value === 'encoders') initEncoders();
    else if (e.target.value === 'hashes') initHashes();
});
themePicker.addEventListener('change', () => {
    document.body.classList.remove('tokyonight', 'gruvbox', 'onedark');
    const val = themePicker.value;
    if (val !== 'default') document.body.classList.add(val);
    localStorage.setItem('selectedTheme', val);
});
window.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('selectedTheme') || 'default';
    if (savedTheme !== 'default') document.body.classList.add(savedTheme);
    themePicker.value = savedTheme;
    const savedCategory = localStorage.getItem('selectedCategory') || 'encoders';
    if (savedCategory === 'hashes') initHashes();
    else initEncoders();
});
