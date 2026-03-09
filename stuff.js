const state = { enc: { file: null }, dec: { file: null } };

function switchTab(mode) {
  document.getElementById('panel-encrypt').style.display = mode === 'encrypt' ? '' : 'none';
  document.getElementById('panel-decrypt').style.display = mode === 'decrypt' ? '' : 'none';
  document.getElementById('tab-enc').classList.toggle('active', mode === 'encrypt');
  document.getElementById('tab-dec').classList.toggle('active', mode === 'decrypt');
}

function handleDragOver(e, id) {
  e.preventDefault();
  document.getElementById('dropzone-' + id).classList.add('dragover');
}
function handleDragLeave(id) {
  document.getElementById('dropzone-' + id).classList.remove('dragover');
}
/* Drag and drop*/
function handleDrop(e, id) {
  e.preventDefault();
  document.getElementById('dropzone-' + id).classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) setFile(id, file);
}

/* File select*/
function handleFileSelect(id) {
  const input = document.getElementById('file-' + id);
  if (input.files[0]) setFile(id, input.files[0]);
}

function setFile(id, file) {
  state[id].file = file;
  const preview = document.getElementById('preview-' + id);
  preview.classList.add('visible');
  document.getElementById('preview-' + id + '-name').textContent = file.name;
  document.getElementById('preview-' + id + '-meta').textContent =
    formatSize(file.size) + '  ·  ' + (file.type || 'Unknown type');
  updateButton(id);
}

function removeFile(id) {
  state[id].file = null;
  document.getElementById('preview-' + id).classList.remove('visible');
  document.getElementById('file-' + id).value = '';
  updateButton(id);
}

function updateButton(id) {
  const key = id === 'enc' ? 'enc' : 'dec';
  const pw = document.getElementById('pw-' + key).value;
  document.getElementById('btn-' + key).disabled = !(state[id].file && pw.length > 0);
}

document.getElementById('pw-enc').addEventListener('input', () => updateButton('enc'));
document.getElementById('pw-dec').addEventListener('input', () => updateButton('dec'));

function togglePw(id, btn) {
  const input = document.getElementById(id);
  if (input.type === 'password') { input.type = 'text'; btn.textContent = '🙈'; }
  else { input.type = 'password'; btn.textContent = '👁'; }
}


/*Password strength*/
function updateStrength(pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 14) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score = Math.min(4, score + 1);

  const colors = ['', '#ff4b4b', '#ff944b', '#ffcc00', '#00ff88'];
  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  for (let i = 1; i <= 4; i++) {
    document.getElementById('sb' + i).style.background = i <= score ? colors[score] : 'var(--border)';
  }
  const lbl = document.getElementById('strength-label');
  lbl.textContent = pw.length ? labels[score] || 'Weak' : '—';
  lbl.style.color = pw.length ? colors[score] : 'var(--muted)';
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function showProgress(id, label, pct) {
  document.getElementById('prog-' + id).classList.add('visible');
  document.getElementById('prog-' + id + '-label').textContent = label;
  document.getElementById('prog-' + id + '-pct').textContent = pct + '%';
  document.getElementById('prog-' + id + '-fill').style.width = pct + '%';
}

function hideProgress(id) {
  document.getElementById('prog-' + id).classList.remove('visible');
}

function showAlert(id, type, msg) {
  const el = document.getElementById('alert-' + id);
  el.className = 'alert alert-' + type + ' visible';
  el.innerHTML = (type === 'success' ? '✅ ' : '❌ ') + msg;
}

function hideAlert(id) {
  document.getElementById('alert-' + id).className = 'alert';
}

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function concatBuffers(...bufs) {
  const total = bufs.reduce((s, b) => s + b.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of bufs) { out.set(new Uint8Array(b), offset); offset += b.byteLength; }
  return out.buffer;
}

/* Turn password into AES-256-GCM key using PBKDF2 */
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', strToBytes(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* IV generation and Encryption algorithm*/
async function encryptFile() {
  hideAlert('enc');
  const file = state.enc.file;
  const password = document.getElementById('pw-enc').value;
  if (!file || !password) return;

  const btn = document.getElementById('btn-enc');
  btn.disabled = true;

  try {
    showProgress('enc', 'Reading file…', 10);
    const fileBuffer = await file.arrayBuffer(); /* Reads file into memory as binary*/

    showProgress('enc', 'Deriving key (PBKDF2)…', 30);
    const salt = crypto.getRandomValues(new Uint8Array(16)); /* 16 byte salt */
    const iv   = crypto.getRandomValues(new Uint8Array(12)); /* 12 byte IV */
    const key  = await deriveKey(password, salt);

    showProgress('enc', 'Encrypting (AES-256-GCM)…', 60);

    const nameBytes = strToBytes(file.name); /* Converts filename to bytes*/
    const nameLenBytes = new Uint8Array(2); /* Filename length stored as 2 bytes */
    new DataView(nameLenBytes.buffer).setUint16(0, nameBytes.length, false);

    const payload = concatBuffers(nameLenBytes.buffer, nameBytes.buffer, fileBuffer);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, payload); /* Actual encryption of payload with IV and key (AES-GCM)*/

    showProgress('enc', 'Packaging output…', 85);

    /* Packaging of output */
    const magic = new TextEncoder().encode('SVAULT01');
    const output = concatBuffers(magic.buffer, salt.buffer, iv.buffer, ciphertext);

    showProgress('enc', 'Done!', 100);
    downloadBlob(new Blob([output], { type: 'application/octet-stream' }), file.name + '.enc');

    setTimeout(() => {
      hideProgress('enc');
      showAlert('enc', 'success', `<b>${file.name}</b> encrypted successfully. Your .enc file is downloading.`);
      btn.disabled = false;
    }, 600);
  } catch (err) {
    hideProgress('enc');
    showAlert('enc', 'error', 'Encryption failed: ' + err.message);
    btn.disabled = false;
  }
} 

/* Decryption algorithm*/
async function decryptFile() {
  hideAlert('dec');
  const file = state.dec.file;
  const password = document.getElementById('pw-dec').value;
  if (!file || !password) return;

  const btn = document.getElementById('btn-dec');
  btn.disabled = true;

  try {
    showProgress('dec', 'Reading file…', 10);
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    const magic = new TextDecoder().decode(bytes.slice(0, 8));
    if (magic !== 'SVAULT01') throw new Error('Not a valid SecuRVault file or file is corrupted.');

    showProgress('dec', 'Extracting parameters…', 25);
    const salt       = bytes.slice(8, 24);
    const iv         = bytes.slice(24, 36);
    const ciphertext = bytes.slice(36);

    showProgress('dec', 'Deriving key (PBKDF2)…', 45);
    const key = await deriveKey(password, salt);

    showProgress('dec', 'Decrypting (AES-256-GCM)…', 65);
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    } catch {
      throw new Error('Wrong password or file has been tampered with. Authentication failed.');
    }

    showProgress('dec', 'Restoring original file…', 85);

    const plain = new Uint8Array(plaintext);
    const nameLen = new DataView(plain.buffer).getUint16(0, false);
    const origName = new TextDecoder().decode(plain.slice(2, 2 + nameLen));
    const fileData = plain.slice(2 + nameLen);

    const ext = origName.split('.').pop().toLowerCase();
    const mimeMap = { pdf:'application/pdf', png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg',
                      gif:'image/gif', txt:'text/plain', html:'text/html', csv:'text/csv',
                      docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                      xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                      mp4:'video/mp4', mp3:'audio/mpeg', zip:'application/zip' };
    const mime = mimeMap[ext] || 'application/octet-stream';

    showProgress('dec', 'Done!', 100);
    downloadBlob(new Blob([fileData], { type: mime }), origName);

    setTimeout(() => {
      hideProgress('dec');
      showAlert('dec', 'success', `<b>${origName}</b> decrypted and restored successfully.`);
      btn.disabled = false;
    }, 600);
  } catch (err) {
    hideProgress('dec');
    showAlert('dec', 'error', err.message);
    btn.disabled = false;
  }
}

/* Download file*/
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

