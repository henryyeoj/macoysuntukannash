const API_URL = 'http://localhost:5000/api';
const SYSTEM_KEY = "CIT-SECURE-1234";

// --- SECURITY STATE ---
let currentPassword = "admin"; 
let failedLoginAttempts = 0;
const MAX_ATTEMPTS = 3;
let lockoutEndTime = null;

// --- APP STATE ---
let vaultData = [];
let auditLogs = [];
let pendingBorrowId = null;

// --- SEARCH & FILTER STATE ---
let currentFilter = "All";
let searchQuery = "";

// --- INITIALIZATION ---
async function initApp() {
    try {
        const configRes = await fetch(`${API_URL}/config`);
        const config = await configRes.json();
        currentPassword = config.pin || "admin"; 

        const itemsRes = await fetch(`${API_URL}/items`);
        vaultData = await itemsRes.json();

        const logsRes = await fetch(`${API_URL}/logs`);
        auditLogs = await logsRes.json();

        const activeRole = sessionStorage.getItem('activeRole');
        if (activeRole) {
            restoreSession(activeRole);
        }
    } catch (error) {
        console.error("⚠️ Make sure your Node backend is running!", error);
    }
}

window.onload = initApp;

function restoreSession(role) {
    if (role === 'admin') {
        setupUI('admin');
    } else if (role === 'student') {
        const sName = sessionStorage.getItem('studentName');
        const sId = sessionStorage.getItem('studentId');
        if(sName && sId) setupUI('student', { name: sName, id: sId });
    }
}

function logoutSession() {
    sessionStorage.clear(); 
    addLog("User Logged Out", "SUCCESS");
    location.reload(); 
}

// --- SECURE LOGIN FLOW ---
function showAdminPortal() {
    document.getElementById('portal-selection').classList.add('hidden');
    document.getElementById('admin-login-screen').classList.remove('hidden');
}

function showStudentPortal() {
    document.getElementById('portal-selection').classList.add('hidden');
    document.getElementById('student-login-screen').classList.remove('hidden');
}

function returnToLanding() {
    document.getElementById('admin-login-screen').classList.add('hidden');
    document.getElementById('student-login-screen').classList.add('hidden');
    document.getElementById('portal-selection').classList.remove('hidden');
    document.getElementById('password-input').value = "";
}

function checkAdminLogin() {
    if (lockoutEndTime && Date.now() < lockoutEndTime) {
        showSecurityAlert(`SYSTEM LOCKED. Try again in ${Math.ceil((lockoutEndTime - Date.now()) / 1000)} seconds.`);
        return;
    }

    const entered = document.getElementById('password-input').value;
    if (entered === currentPassword) {
        failedLoginAttempts = 0;
        sessionStorage.setItem('activeRole', 'admin');
        addLog("Administrator Login Verified", "SUCCESS");
        setupUI('admin');
    } else {
        failedLoginAttempts++;
        document.getElementById('password-input').value = "";
        if (failedLoginAttempts >= MAX_ATTEMPTS) {
            lockoutEndTime = Date.now() + 30000; 
            failedLoginAttempts = 0; 
            addLog("BRUTE FORCE DETECTED: Admin Lockout Triggered", "SECURITY ALERT");
            showSecurityAlert("MAXIMUM ATTEMPTS EXCEEDED. SYSTEM LOCKED FOR 30 SECONDS.");
            startLockoutTimer();
        } else {
            addLog(`Failed Admin Entry Attempt (${failedLoginAttempts}/${MAX_ATTEMPTS})`, "SECURITY ALERT");
            showSecurityAlert(`Incorrect Password. ${MAX_ATTEMPTS - failedLoginAttempts} attempts remaining.`);
        }
    }
}

function startLockoutTimer() {
    const btn = document.getElementById('btn-admin-login');
    const timerText = document.getElementById('lockout-timer');
    btn.disabled = true;
    
    const interval = setInterval(() => {
        let remaining = Math.ceil((lockoutEndTime - Date.now()) / 1000);
        if (remaining <= 0) {
            clearInterval(interval);
            btn.disabled = false;
            timerText.innerText = "";
            lockoutEndTime = null;
        } else {
            timerText.innerText = `LOCKED: Please wait ${remaining}s`;
        }
    }, 1000);
}

function checkStudentLogin() {
    const n = document.getElementById('student-name').value.trim();
    const sid = document.getElementById('student-id').value.trim();
    if (n && sid) {
        sessionStorage.setItem('activeRole', 'student');
        sessionStorage.setItem('studentName', n);
        sessionStorage.setItem('studentId', sid);
        addLog(`Student Login: ${n} (ID: ${sid})`, "SUCCESS");
        setupUI('student', { name: n, id: sid });
    } else { alert("Please enter both Name and Student ID."); }
}

// --- UI DASHBOARD SETUP ---
function setupUI(role, studentData = null) {
    document.getElementById('landing-container').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    
    const isAdmin = (role === 'admin');
    
    // Hide original admin form components
    document.getElementById('admin-controls').classList.toggle('hidden', !isAdmin);
    document.getElementById('audit-log-container').classList.toggle('hidden', !isAdmin);
    document.getElementById('admin-analytics').classList.toggle('hidden', !isAdmin);
    
    // Hide specific elements tagged for Admin only
    const adminElements = document.querySelectorAll('.admin-only');
    adminElements.forEach(el => el.classList.toggle('hidden', !isAdmin));

    // Dynamically change the table title based on the role
    const tableTitle = document.querySelector('.table-tools .section-title');
    if (tableTitle) {
        tableTitle.innerText = isAdmin ? "Secure Vault (3DES Protected)" : "Available Equipment";
    }

    // Set greeting
    document.getElementById('user-greeting').innerHTML = isAdmin
        ? "Admin Access Verified"
        : `Student: <span style="color: #10b981;">${studentData.name}</span>`;
    
    if (isAdmin) renderAuditLogs();
    applyFilters(); 
}

function showSecurityAlert(msg) {
    document.getElementById('security-alert-message').innerText = msg;
    document.getElementById('security-alert').classList.remove('hidden');
}

// --- 3DES ENGINE ---
function xorStrings(t, k) {
    let r = '';
    for (let i = 0; i < t.length; i++) { r += String.fromCharCode((t.charCodeAt(i) ^ k.charCodeAt(i % k.length)) % 256); }
    return r;
}

function runFeistel16(block, key) {
    let padded = block.padEnd(8, ' ').substring(0, 8);
    let L = padded.substring(0, 4), R = padded.substring(4, 8);
    for (let i = 0; i < 16; i++) {
        let temp = R;
        R = xorStrings(L, xorStrings(R, key));
        L = temp;
    }
    return R + L;
}

// --- BULLETPROOF VISUALIZER FIX ---
async function apply3DESWithVisuals(text) {
    const viz = document.getElementById('encryption-visualizer');
    const resultBox = document.getElementById('viz-result');
    const step1 = document.getElementById('step-1');
    const step2 = document.getElementById('step-2');
    const step3 = document.getElementById('step-3');
    
    if (viz) viz.classList.remove('hidden');
    
    // Phase 1
    if (step1) step1.classList.add('active');
    let s1 = runFeistel16(text, SYSTEM_KEY);
    if (resultBox) resultBox.innerText = "K1 Applied: " + btoa(s1).substring(0,10) + "...";
    await new Promise(r => setTimeout(r, 600));

    // Phase 2
    if (step2) step2.classList.add('active');
    let s2 = runFeistel16(s1, SYSTEM_KEY.split('').reverse().join(''));
    if (resultBox) resultBox.innerText = "K2 Inverse Applied: " + btoa(s2).substring(0,10) + "...";
    await new Promise(r => setTimeout(r, 600));

    // Phase 3
    if (step3) step3.classList.add('active');
    let s3 = runFeistel16(s2, SYSTEM_KEY);
    const finalCipher = "3DES-" + btoa(s3);
    if (resultBox) resultBox.innerText = "Final 3DES Cipher: " + finalCipher;
    await new Promise(r => setTimeout(r, 800));

    if (viz) viz.classList.add('hidden');
    
    // Cleanup
    if (step1) step1.classList.remove('active');
    if (step2) step2.classList.remove('active');
    if (step3) step3.classList.remove('active');
    
    return finalCipher;
}

function decrypt3DES(enc) {
    try {
        let raw = atob(enc.replace("3DES-", ""));
        let st1 = runFeistel16(raw, SYSTEM_KEY);
        let st2 = runFeistel16(st1, SYSTEM_KEY.split('').reverse().join(''));
        let st3 = runFeistel16(st2, SYSTEM_KEY);
        return st3.trim();
    } catch (e) { return "Error"; }
}

// --- LOGGING ---
async function addLog(action, status) {
    const timestamp = new Date().toLocaleString();
    const newLog = { action, status, timestamp };
    try {
        const res = await fetch(`${API_URL}/logs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newLog)
        });
        const savedLog = await res.json();
        auditLogs.unshift(savedLog);
        renderAuditLogs();
    } catch(err) { console.error(err); }
}

function renderAuditLogs() {
    const logDiv = document.getElementById('audit-list');
    if (logDiv) {
        logDiv.innerHTML = auditLogs.map(log => {
            let color = log.status === 'SUCCESS' ? '#10b981' : (log.status === 'DELETED' ? '#dc2626' : '#ef4444');
            return `[${log.timestamp}] <span style="color:${color}; font-weight:bold;">${log.status}</span>: ${log.action}`;
        }).join('<br><br>');
    }
}

// --- SEARCH & ANALYTICS ---
function handleSearch() {
    searchQuery = document.getElementById('search-input').value.toLowerCase();
    applyFilters();
}

function filterByStatus(s) {
    currentFilter = s;
    
    // Manage active state of pills (Fixed matching for "Pending")
    document.querySelectorAll('.filter-pills .pill').forEach(btn => {
        btn.classList.remove('active');
        
        let btnText = btn.innerText.trim();
        if (btnText === s || (s === 'Pending Approval' && btnText === 'Pending')) {
            btn.classList.add('active');
        }
    });

    applyFilters();
}

function applyFilters() {
    if(sessionStorage.getItem('activeRole') === 'admin') updateAnalytics();

    let filteredData = vaultData.filter(item => {
        let matchesStatus = currentFilter === 'All' ? true : item.status === currentFilter;
        let matchesSearch = item.equipment.toLowerCase().includes(searchQuery);
        return matchesStatus && matchesSearch;
    });

    updateTable(filteredData);
}

function updateAnalytics() {
    document.getElementById('stat-total').innerText = vaultData.length;
    document.getElementById('stat-borrowed').innerText = vaultData.filter(i => i.status === 'Borrowed').length;
    document.getElementById('stat-pending').innerText = vaultData.filter(i => i.status === 'Pending Approval').length;

    let totalPenalties = 0;
    vaultData.forEach(item => {
        if (item.status === 'Borrowed' && item.returnDate) {
            const today = new Date(); today.setHours(0,0,0,0);
            const returnD = new Date(item.returnDate + "T00:00:00");
            const diffDays = Math.ceil((today - returnD) / (1000*60*60*24));
            if(diffDays > 0) totalPenalties += (diffDays * 50);
        }
    });
    document.getElementById('stat-penalties').innerText = `₱${totalPenalties}`;
}

// --- TABLE RENDERING ---
function updateTable(dataToDisplay, role = sessionStorage.getItem('activeRole'), studentData = {name: sessionStorage.getItem('studentName')}) {
    const thead = document.querySelector('#vault-table thead');
    const list = document.getElementById('inventory-list');
    const isAdmin = (role === 'admin');

    // 1. Update the headers with Category
    thead.innerHTML = isAdmin ?
        `<tr><th>#</th><th>Equipment</th><th>Category</th><th>Description</th><th>Price</th><th>Encrypted Serial (3DES)</th><th>Status</th><th>Action</th></tr>` :
        `<tr><th>#</th><th>Equipment</th><th>Category</th><th>Description</th><th>Status</th><th>Action</th></tr>`;

    list.innerHTML = "";
    dataToDisplay.forEach((item, index) => {
        let row = `<tr><td>${index+1}</td><td><strong>${item.equipment}</strong></td>`;
        
        // 2. Prepare the new column HTML (Category, Description, Price)
        let catHtml = `<td><span style="font-size: 0.8rem; background: #e2e8f0; padding: 4px 8px; border-radius: 6px; color: #475569; white-space: nowrap;">${item.category || 'Others'}</span></td>`;
        let descHtml = `<td>${item.description || '<span style="color:#cbd5e1;font-size:0.8rem;">No Description</span>'}</td>`;
        let priceHtml = `<td>₱${item.price || 0}</td>`;

        let badgeClass = 'badge-available';
        if (item.status === 'Borrowed') badgeClass = 'badge-borrowed';
        if (item.status === 'Pending Approval') badgeClass = 'badge-pending';
        if (item.status === 'Maintenance') badgeClass = 'badge-maintenance';
        
        let penaltyText = "";
        if (item.status === 'Borrowed' && item.returnDate) {
            const today = new Date(); today.setHours(0, 0, 0, 0); 
            const returnD = new Date(item.returnDate + "T00:00:00"); 
            const diffDays = Math.ceil((today - returnD) / (1000 * 60 * 60 * 24));
            
            if (diffDays > 0) {
                penaltyText = `<br><span style="color: #ef4444; font-size: 0.75rem;"> Overdue! (₱${diffDays * 50})</span>`;
            } else {
                penaltyText = `<br><small style="color: #64748b;">Due: ${item.returnDate}</small>`;
            }
        }
        
        let statusHtml = `<span class="badge ${badgeClass}">${item.status}</span>`;
        if(item.borrower) statusHtml += `<br><small>By: ${item.borrower}</small>`;
        if(item.status === 'Borrowed') statusHtml += penaltyText;

        if (isAdmin) {
            let displaySerial = item.serials[0];
            let shortSerial = displaySerial.length > 25 ? displaySerial.substring(0, 25) + '...' : displaySerial;
            let actionHtml = '';
            
            if (item.status === 'Pending Approval') {
                actionHtml = `<button onclick="acceptRequest('${item._id}')" class="btn-action-sm" style="background:#10b981;">Accept</button>
                              <button onclick="rejectRequest('${item._id}')" class="btn-action-sm" style="background:#ef4444;">Reject</button>`;
            } else if (item.status === 'Available') {
                actionHtml = `<button onclick="toggleMaintenance('${item._id}')" class="btn-action-sm" style="background:#f59e0b; color:white;">Set Maintenance</button>
                              <button onclick="removeItem('${item._id}')" class="btn-delete-row" style="margin-top:5px;">Delete</button>`;
            } else if (item.status === 'Maintenance') {
                actionHtml = `<button onclick="toggleMaintenance('${item._id}')" class="btn-action-sm" style="background:#10b981;">Make Available</button>
                              <button onclick="removeItem('${item._id}')" class="btn-delete-row" style="margin-top:5px;">Delete</button>`;
            } else {
                actionHtml = `<button onclick="removeItem('${item._id}')" class="btn-delete-row">Delete</button>`;
            }
            
            // 3. Inject Category, Description, and Price into the Admin row
            row += `${catHtml}${descHtml}${priceHtml}<td style="cursor:pointer; font-family:monospace; color:#3b82f6;" title="Click to Decrypt" onclick="unlockItem('${item._id}')">${shortSerial}</td>
                    <td>${statusHtml}</td><td>${actionHtml}</td>`;
        } else {
            let btn = '';
            if (item.status === 'Available') {
                btn = `<button onclick="borrowItem('${item._id}')" class="btn-borrow">Borrow</button>`;
            } else if (item.status === 'Pending Approval' && item.borrower === studentData.name) {
                btn = `<span style="font-size: 0.8rem; color: #6366f1; font-weight: bold;">Waiting...</span>`;
            } else if (item.status === 'Borrowed' && item.borrower === studentData.name) {
                btn = `<button onclick="returnItem('${item._id}')" class="btn-return">Return</button>`;
            } else {
                btn = `<span style="font-size: 0.8rem; color: #64748b;">Unavailable</span>`;
            }
            // 4. Inject Category and Description into the Student row
            row += `${catHtml}${descHtml}<td>${statusHtml}</td><td>${btn}</td>`;
        }
        list.innerHTML += row + "</tr>";
    });
}

// --- DATABASE ACTIONS ---
async function addNewItem() {
    const n = document.getElementById('item-name').value.trim();
    const s = document.getElementById('item-serial').value.trim();
    const desc = document.getElementById('item-description').value.trim(); 
    const price = document.getElementById('item-price').value.trim();      
    const cat = document.getElementById('item-category').value; // NEW: Get category value

    if (!n || !s || !desc || !price || !cat) { 
        alert("Action Denied: Name, Serial, Description, Price, and Category are required."); 
        return; 
    }

    const encryptedSerial = await apply3DESWithVisuals(s);
    const newItem = { 
        equipment: n, 
        category: cat,         // NEW: Save category
        description: desc,     
        price: Number(price),  
        serials: [encryptedSerial], 
        status: 'Available' 
    };

    try {
        const res = await fetch(`${API_URL}/items`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newItem) });
        const savedItem = await res.json();
        vaultData.push(savedItem);
        addLog(`Registered: ${n} (3DES Protected)`, "SUCCESS");
        
        // Clear all fields and reset dropdown
        document.getElementById('item-name').value = "";
        document.getElementById('item-serial').value = "";
        document.getElementById('item-description').value = ""; 
        document.getElementById('item-price').value = "";       
        document.getElementById('item-category').value = "End-User Devices"; 
        
        applyFilters(); 
    } catch(err) { console.error(err); }
}

function unlockItem(id) {
    const item = vaultData.find(i => i._id === id);
    const decryptedSerial = decrypt3DES(item.serials[0]);
    addLog(`Decrypted ${item.equipment}`, "SUCCESS");
    alert(`🔓 Original Serial: ${decryptedSerial}`);
}

async function acceptRequest(id) {
    let item = vaultData.find(i => i._id === id);
    item.status = 'Borrowed';
    try {
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        addLog(`Approved request for ${item.equipment} by ${item.borrower}`, "SUCCESS");
        applyFilters();
    } catch(err) { console.error(err); }
}

async function rejectRequest(id) {
    let item = vaultData.find(i => i._id === id);
    let studentName = item.borrower;
    item.status = 'Available'; item.borrower = ''; item.returnDate = '';
    try {
        await fetch(`${API_URL}/items/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        addLog(`Rejected request for ${item.equipment} by ${studentName}`, "DELETED");
        applyFilters();
    } catch(err) { console.error(err); }
}

async function removeItem(id) {
    if(confirm("Delete item?")) {
        await fetch(`${API_URL}/items/${id}`, { method: 'DELETE' });
        vaultData = vaultData.filter(i => i._id !== id);
        applyFilters();
    }
}

async function toggleMaintenance(id) {
    let item = vaultData.find(i => i._id === id);
    item.status = item.status === 'Maintenance' ? 'Available' : 'Maintenance';
    
    try {
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        addLog(`Status changed to ${item.status}: ${item.equipment}`, "SUCCESS");
        applyFilters();
    } catch(err) { console.error(err); }
}

function borrowItem(id) {
    pendingBorrowId = id;
    document.getElementById('borrow-modal').classList.remove('hidden');
}

async function confirmBorrow() {
    const date = document.getElementById('return-date-field').value;
    if(!date) return alert("Select return date.");
    
    let item = vaultData.find(i => i._id === pendingBorrowId);
    item.status = 'Pending Approval';
    item.borrower = sessionStorage.getItem('studentName');
    item.returnDate = date;

    try {
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        addLog(`Requested by ${sessionStorage.getItem('studentName')}: ${item.equipment}`, "SUCCESS");
        closeBorrowModal();
        applyFilters();
    } catch(err) { console.error(err); }
}

async function returnItem(id) {
    let item = vaultData.find(i => i._id === id);
    if (item.returnDate) {
        const today = new Date(); today.setHours(0, 0, 0, 0);
        const returnD = new Date(item.returnDate + "T00:00:00");
        const diffDays = Math.ceil((today - returnD) / (1000 * 60 * 60 * 24));
        if (diffDays > 0) alert(` OVERDUE ITEM DETECTED!\n\nPlease proceed to the Administrator to pay the penalty fee of ₱${diffDays * 50}.`);
    }
    
    addLog(`Returned by ${item.borrower}: ${item.equipment}`, "SUCCESS");
    item.status = 'Available'; item.borrower = ''; item.returnDate = '';
    
    try {
        await fetch(`${API_URL}/items/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        applyFilters();
    } catch(err) { console.error(err); }
}

// --- CONFIG SETTINGS ---
async function saveNewPassword() {
    const oldPass = document.getElementById('old-password-field').value;
    const newPass = document.getElementById('new-password-field').value;
    
    if (!oldPass || !newPass) { 
        alert("Please fill in both fields."); return; 
    }

    if (oldPass === currentPassword) {
        currentPassword = newPass;
        await fetch(`${API_URL}/config`, { 
            method: 'PUT', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify({ pin: currentPassword }) 
        });
        
        addLog("Admin Password Changed", "SUCCESS"); 
        alert("Password Updated!"); 
        closePasswordModal();
    } else {
        addLog("Failed Password Update Attempt", "SECURITY ALERT");
        alert("Incorrect Old Password.");
    }
}

// --- MODAL CONTROLS ---
function closeAlert() { document.getElementById('security-alert').classList.add('hidden'); }
function openPasswordModal() { document.getElementById('password-modal').classList.remove('hidden'); }
function closePasswordModal() { document.getElementById('password-modal').classList.add('hidden'); }
function closeBorrowModal() { document.getElementById('borrow-modal').classList.add('hidden'); }
function handleLoginEnter(e) { if(e.key === 'Enter') checkAdminLogin(); }
function handleAddItemEnter(e) { if(e.key === 'Enter') addNewItem(); }
function handleUpdatePasswordEnter(e) { if(e.key === 'Enter') { e.preventDefault(); saveNewPassword(); } }

// --- SCROLL TO TOP UTILITY ---
window.onscroll = function() { toggleScrollButton() };

function toggleScrollButton() {
    const btn = document.getElementById("scroll-top-btn");
    if (document.body.scrollTop > 200 || document.documentElement.scrollTop > 200) {
        btn.style.display = "block";
    } else {
        btn.style.display = "none";
    }
}

function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth' 
    });
}

// --- SIDEBAR INTERACTIVITY ---
document.addEventListener('DOMContentLoaded', () => {
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from all links
            navItems.forEach(nav => nav.classList.remove('active'));
            // Add active class to the clicked link
            this.classList.add('active');
        });
    });
});