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
let shoppingCart = []; 
let pendingReportId = null;
let pendingMaintenanceId = null;

let categoryChartInstance = null; 
let popularChartInstance = null; 

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

        // Start the global live countdown clock & progress bars
        startLiveCountdown();

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
    addLog("User Logged Out", "SUCCESS", sessionStorage.getItem('studentName') || 'admin');
    sessionStorage.clear(); 
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
        addLog("Administrator Login Verified", "SUCCESS", "admin");
        setupUI('admin');
    } else {
        failedLoginAttempts++;
        document.getElementById('password-input').value = "";
        if (failedLoginAttempts >= MAX_ATTEMPTS) {
            lockoutEndTime = Date.now() + 30000; 
            failedLoginAttempts = 0; 
            addLog("BRUTE FORCE DETECTED: Admin Lockout Triggered", "SECURITY ALERT", "system");
            showSecurityAlert("MAXIMUM ATTEMPTS EXCEEDED. SYSTEM LOCKED FOR 30 SECONDS.");
            startLockoutTimer();
        } else {
            addLog(`Failed Admin Entry Attempt (${failedLoginAttempts}/${MAX_ATTEMPTS})`, "SECURITY ALERT", "system");
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
        addLog(`Student Login: ${n} (ID: ${sid})`, "SUCCESS", n);
        setupUI('student', { name: n, id: sid });
    } else { alert("Please enter both Name and Student ID."); }
}

// --- UI DASHBOARD SETUP ---
function setupUI(role, studentData = null) {
    document.getElementById('landing-container').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    
    const isAdmin = (role === 'admin');
    
    const adminElements = document.querySelectorAll('.admin-only');
    adminElements.forEach(el => el.classList.toggle('hidden', !isAdmin));

    const studentElements = document.querySelectorAll('.student-only');
    studentElements.forEach(el => el.classList.toggle('hidden', isAdmin));

    const tableTitle = document.querySelector('.table-tools .section-title');
    if (tableTitle) {
        tableTitle.innerText = isAdmin ? "Secure Vault (3DES Protected)" : "Available Equipment";
    }

    document.getElementById('user-greeting').innerHTML = isAdmin
        ? "Admin Access Verified"
        : `Student: <span style="color: #10b981;">${studentData.name}</span>`;
    
    switchNav('home');
    
    if (isAdmin) {
        renderAuditLogs();
    } else {
        updateStudentHistory();
        updateCartBadge();
    }
    applyFilters(); 
}

function showSecurityAlert(msg) {
    document.getElementById('security-alert-message').innerText = msg;
    document.getElementById('security-alert').classList.remove('hidden');
}

function switchNav(view) {
    document.getElementById('nav-home').classList.remove('active');
    document.getElementById('nav-maintenance').classList.remove('active');
    document.getElementById('nav-charts').classList.remove('active');
    if(document.getElementById('nav-requests')) document.getElementById('nav-requests').classList.remove('active');
    
    if(document.getElementById(`nav-${view}`)) document.getElementById(`nav-${view}`).classList.add('active');

    document.getElementById('view-home').classList.add('hidden');
    document.getElementById('view-maintenance').classList.add('hidden');
    document.getElementById('view-charts').classList.add('hidden');
    document.getElementById('view-requests').classList.add('hidden');
    
    document.getElementById(`view-${view}`).classList.remove('hidden');

    if (view === 'charts') updateChart();
    if (view === 'requests') renderRequestsView();
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

async function apply3DESWithVisuals(text) {
    const viz = document.getElementById('encryption-visualizer');
    const resultBox = document.getElementById('viz-result');
    const step1 = document.getElementById('step-1');
    const step2 = document.getElementById('step-2');
    const step3 = document.getElementById('step-3');
    
    if (viz) viz.classList.remove('hidden');
    
    if (step1) step1.classList.add('active');
    let s1 = runFeistel16(text, SYSTEM_KEY);
    if (resultBox) resultBox.innerText = "K1 Applied: " + btoa(s1).substring(0,10) + "...";
    await new Promise(r => setTimeout(r, 600));

    if (step2) step2.classList.add('active');
    let s2 = runFeistel16(s1, SYSTEM_KEY.split('').reverse().join(''));
    if (resultBox) resultBox.innerText = "K2 Inverse Applied: " + btoa(s2).substring(0,10) + "...";
    await new Promise(r => setTimeout(r, 600));

    if (step3) step3.classList.add('active');
    let s3 = runFeistel16(s2, SYSTEM_KEY);
    const finalCipher = "3DES-" + btoa(s3);
    if (resultBox) resultBox.innerText = "Final 3DES Cipher: " + finalCipher;
    await new Promise(r => setTimeout(r, 800));

    if (viz) viz.classList.add('hidden');
    
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

// --- LOGGING & HISTORY ---
async function addLog(action, status, relatedUser = 'admin') {
    const timestamp = new Date().toLocaleString();
    const newLog = { action, status, user: relatedUser, timestamp };
    try {
        const res = await fetch(`${API_URL}/logs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newLog) });
        const savedLog = await res.json();
        auditLogs.unshift(savedLog);
        
        if(sessionStorage.getItem('activeRole') === 'admin') renderAuditLogs();
        if(sessionStorage.getItem('activeRole') === 'student') updateStudentHistory();
        
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

function updateStudentHistory() {
    const list = document.getElementById('student-history-list');
    if (!list) return;

    const myName = sessionStorage.getItem('studentName');
    const myLogs = auditLogs.filter(log => log.user === myName);
    
    if(myLogs.length === 0) {
        list.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 20px; color:#64748b;">No past transactions found.</td></tr>`;
        return;
    }
    
    list.innerHTML = myLogs.map(log => {
        let badgeClass = 'badge-available'; 
        if (log.status === 'PENDING' || log.action.includes('Requested') || log.action.includes('Reported')) badgeClass = 'badge-pending';
        if (log.status === 'DELETED' || log.action.includes('Rejected')) badgeClass = 'badge-maintenance'; 
        
        return `<tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 15px;"><small style="color:#64748b;">${log.timestamp}</small></td>
            <td style="padding: 12px 15px;"><strong>${log.action}</strong></td>
            <td style="padding: 12px 15px;"><span class="badge ${badgeClass}">${log.status}</span></td>
        </tr>`;
    }).join('');
}


// --- LIVE COUNTDOWN ENGINE (PENALTY WATCH + PROGRESS BAR) ---
function startLiveCountdown() {
    setInterval(() => {
        // 1. Text Update & Row Flash Logic
        document.querySelectorAll('.countdown-timer').forEach(el => {
            const returnDateStr = el.getAttribute('data-date');
            if (!returnDateStr) return;
            
            const targetTime = new Date(returnDateStr + "T23:59:59").getTime();
            const now = new Date().getTime();
            const diff = targetTime - now;
            let tr = el.closest('tr');

            if (diff < 0) {
                // OVERDUE
                const daysOverdue = Math.ceil(Math.abs(diff) / (1000 * 60 * 60 * 24));
                const penalty = daysOverdue * 50;
                el.innerHTML = `⏳ Overdue by ${daysOverdue} day(s) (₱${penalty} Penalty)`;
                el.className = 'countdown-timer pulse-red';
                el.style.color = '#ef4444';
                el.style.fontWeight = 'bold';
                if(tr) tr.classList.add('row-overdue');
            } else {
                // ACTIVE
                if(tr) tr.classList.remove('row-overdue');
                const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                const secs = Math.floor((diff % (1000 * 60)) / 1000);
                
                let timeText = `⏳ `;
                if (days > 0) timeText += `${days}d `;
                timeText += `${hours}h ${mins}m ${secs}s left`;

                el.innerHTML = timeText;

                if (diff < 12 * 60 * 60 * 1000) { 
                    el.style.color = '#ef4444'; 
                    el.className = 'countdown-timer';
                } else if (diff < 2 * 24 * 60 * 60 * 1000) { 
                    el.style.color = '#f59e0b'; 
                    el.className = 'countdown-timer';
                } else {
                    el.style.color = '#10b981'; 
                    el.className = 'countdown-timer';
                }
            }
        });

        // 2. Visual Horizontal Progress Bar Logic
        document.querySelectorAll('.progress-fill').forEach(fill => {
            const returnDateStr = fill.getAttribute('data-date');
            if (!returnDateStr) return;
            
            const targetTime = new Date(returnDateStr + "T23:59:59").getTime();
            const now = new Date().getTime();
            const diff = targetTime - now;

            // Base the full bar width on a standard 7-day total borrow time
            const maxTime = 7 * 24 * 60 * 60 * 1000; 
            let percent = (diff / maxTime) * 100;
            if (percent > 100) percent = 100;
            if (percent < 0) percent = 0;

            fill.style.width = `${percent}%`;

            if (diff < 0) fill.style.background = '#dc2626'; // Overdue Dark Red
            else if (diff < 12 * 60 * 60 * 1000) fill.style.background = '#ef4444'; // Red
            else if (diff < 2 * 24 * 60 * 60 * 1000) fill.style.background = '#f59e0b'; // Yellow
            else fill.style.background = '#10b981'; // Green
        });

    }, 1000);
}


// --- SMART CART (STUDENT) ---
function updateCartBadge() {
    let totalItems = shoppingCart.reduce((sum, i) => sum + i.reqQty, 0);
    document.getElementById('cart-count').innerText = totalItems;
    document.getElementById('btn-cart').style.background = totalItems > 0 ? '#f59e0b' : 'var(--cit-blue)';
}

function addToCart(id) {
    const item = vaultData.find(i => i._id === id);
    if (!item || item.status !== 'Available') return;

    let stock = item.serials.length;
    let existingCartItem = shoppingCart.find(i => i.id === id);

    if (existingCartItem) {
        if (existingCartItem.reqQty < stock) {
            existingCartItem.reqQty++;
            updateCartBadge();
            alert(`Increased ${item.equipment} quantity in bag.`);
        } else {
            alert(`Cannot add more. Only ${stock} available in stock.`);
        }
    } else {
        shoppingCart.push({ id: id, equipment: item.equipment, category: item.category || 'Others', maxQty: stock, reqQty: 1 });
        updateCartBadge();
        alert(`Added ${item.equipment} to your Equipment Bag 🛒`);
    }
}

function openCartModal() {
    const list = document.getElementById('cart-list');
    
    if (shoppingCart.length === 0) {
        list.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 20px; color:#64748b;">Your bag is completely empty.</td></tr>`;
    } else {
        list.innerHTML = shoppingCart.map((cartItem) => {
            return `
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 10px;"><strong>${cartItem.equipment}</strong></td>
                <td style="padding: 10px;"><span style="font-size: 0.75rem; background: #e2e8f0; padding: 4px 6px; border-radius: 4px; color: #475569;">${cartItem.category}</span></td>
                <td style="padding: 10px; text-align:center;">
                    <input type="number" min="1" max="${cartItem.maxQty}" value="${cartItem.reqQty}" 
                           onchange="updateCartQty('${cartItem.id}', this.value)" 
                           style="width: 50px; padding: 5px; border-radius: 4px; border: 1px solid var(--border); text-align: center;">
                </td>
                <td style="padding: 10px; text-align:center;">
                    <button onclick="removeFromCart('${cartItem.id}')" style="background: none; border: none; color: #ef4444; font-size: 1rem; cursor: pointer;">✖</button>
                </td>
            </tr>`;
        }).join('');
    }

    document.getElementById('cart-total-badge').innerText = `${shoppingCart.reduce((s, i) => s + i.reqQty, 0)} Items`;
    document.getElementById('cart-modal').classList.remove('hidden');
}

function closeCartModal() { document.getElementById('cart-modal').classList.add('hidden'); }

function updateCartQty(id, newQty) {
    let item = shoppingCart.find(i => i.id === id);
    newQty = parseInt(newQty);
    if (newQty > item.maxQty) newQty = item.maxQty;
    if (newQty < 1) newQty = 1;
    item.reqQty = newQty;
    
    document.getElementById('cart-total-badge').innerText = `${shoppingCart.reduce((s, i) => s + i.reqQty, 0)} Items`;
    updateCartBadge();
}

function removeFromCart(id) {
    shoppingCart = shoppingCart.filter(i => i.id !== id);
    updateCartBadge();
    openCartModal(); 
}

function clearCart() {
    shoppingCart = [];
    updateCartBadge();
    openCartModal();
}

async function checkoutCart() {
    if (shoppingCart.length === 0) return alert('Your Equipment Bag is empty.');
    
    const returnDate = document.getElementById('cart-return-date').value;
    if (!returnDate) return alert("Please select an Expected Return Date.");
    
    const purpose = document.getElementById('cart-purpose').value || "General Laboratory Work";
    const studentName = sessionStorage.getItem('studentName');
    const transactionId = "TXN-" + Math.floor(10000 + Math.random() * 90000); 

    for (let cartItem of shoppingCart) {
        let originalItem = vaultData.find(i => i._id === cartItem.id);
        if (!originalItem) continue;

        if (cartItem.reqQty < originalItem.serials.length) {
            let poppedSerials = originalItem.serials.splice(0, cartItem.reqQty);
            await fetch(`${API_URL}/items/${originalItem._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(originalItem) });

            const batchRequest = {
                equipment: originalItem.equipment, category: originalItem.category, description: originalItem.description, price: originalItem.price,
                serials: poppedSerials, status: 'Pending Approval', borrower: studentName, returnDate: returnDate,
                transactionId: transactionId, purpose: purpose
            };
            await fetch(`${API_URL}/items`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(batchRequest) });

        } else {
            originalItem.status = 'Pending Approval';
            originalItem.borrower = studentName;
            originalItem.returnDate = returnDate;
            originalItem.transactionId = transactionId;
            originalItem.purpose = purpose;
            await fetch(`${API_URL}/items/${originalItem._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(originalItem) });
        }
    }

    addLog(`Requested Cart Checkout (${shoppingCart.length} items) - [${transactionId}]`, "PENDING", studentName);
    
    clearCart();
    closeCartModal();
    alert("Checkout Successful! Your request has been sent to the Administrator.");
    
    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}


// --- ADMIN: TRANSACTIONS / REQUESTS VIEW ---
function renderRequestsView() {
    const container = document.getElementById('requests-container');
    const pendingData = vaultData.filter(i => i.status === 'Pending Approval');

    if (pendingData.length === 0) {
        container.innerHTML = `<div style="text-align:center; padding: 40px; color:#64748b; background: #f8fafc; border-radius: 12px; border: 1px dashed var(--border);">There are no pending borrow requests at this time.</div>`;
        return;
    }

    let groupedRequests = {};
    pendingData.forEach(item => {
        let tx = item.transactionId || 'LEGACY-REQUEST';
        if (!groupedRequests[tx]) {
            groupedRequests[tx] = { transactionId: tx, borrower: item.borrower, returnDate: item.returnDate, purpose: item.purpose || 'Not provided', items: [] };
        }
        groupedRequests[tx].items.push(item);
    });

    let html = '';
    for (let tx in groupedRequests) {
        let group = groupedRequests[tx];
        
        let itemRows = group.items.map(i => {
            return `<tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 8px;"><strong>${i.equipment}</strong> <span style="color:#64748b; font-size:0.8rem;">(${i.category})</span></td>
                <td style="padding: 8px; text-align:center;"><span style="font-weight:bold; color:var(--cit-blue); background:#e2e8f0; padding:4px 10px; border-radius:20px;">${i.serials.length}</span></td>
            </tr>`;
        }).join('');

        html += `
        <div style="border: 1px solid var(--border); border-radius: 12px; overflow: hidden; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
            <div style="background: #f8fafc; padding: 15px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0; color: var(--cit-blue); font-size: 1.1rem;">${group.transactionId}</h3>
                    <p style="margin: 5px 0 0 0; font-size: 0.85rem; color: #64748b;">
                        <strong>Student:</strong> ${group.borrower} &nbsp;|&nbsp; 
                        <strong>Return:</strong> ${group.returnDate} &nbsp;|&nbsp; 
                        <strong>Purpose:</strong> ${group.purpose}
                    </p>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button onclick="approveTransaction('${group.transactionId}')" class="btn-primary" style="background:#10b981; padding: 8px 15px; font-size: 0.85rem;">Approve All</button>
                    <button onclick="rejectTransaction('${group.transactionId}')" class="btn-danger" style="padding: 8px 15px; font-size: 0.85rem;">Reject All</button>
                </div>
            </div>
            <div style="padding: 15px 20px;">
                <table style="width: 100%; text-align: left; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--border); color: #64748b; font-size: 0.8rem;">
                            <th style="padding: 8px;">Requested Equipment</th>
                            <th style="padding: 8px; text-align:center;">Requested Qty</th>
                        </tr>
                    </thead>
                    <tbody>${itemRows}</tbody>
                </table>
            </div>
        </div>`;
    }
    container.innerHTML = html;
}

async function approveTransaction(txId) {
    let itemsToApprove = vaultData.filter(i => i.status === 'Pending Approval' && i.transactionId === txId);
    let borrowerName = "";
    for (let item of itemsToApprove) {
        borrowerName = item.borrower;
        item.status = 'Borrowed';
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
    }
    addLog(`Approved batch request [${txId}] for ${borrowerName}`, "SUCCESS", borrowerName);
    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}

async function rejectTransaction(txId) {
    if(!confirm("Are you sure you want to completely reject and cancel this entire request?")) return;
    let itemsToReject = vaultData.filter(i => i.status === 'Pending Approval' && i.transactionId === txId);
    let borrowerName = "";

    for (let item of itemsToReject) {
        borrowerName = item.borrower;
        const existingAvailableGroup = vaultData.find(i => i.equipment.toLowerCase() === item.equipment.toLowerCase() && i.status === 'Available' && i._id !== item._id);
        
        if (existingAvailableGroup) {
            existingAvailableGroup.serials.push(...item.serials);
            await fetch(`${API_URL}/items/${existingAvailableGroup._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(existingAvailableGroup) });
            await fetch(`${API_URL}/items/${item._id}`, { method: 'DELETE' });
        } else {
            item.status = 'Available'; item.borrower = ''; item.returnDate = ''; item.transactionId = ''; item.purpose = '';
            await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        }
    }
    addLog(`Rejected batch request [${txId}] by ${borrowerName}`, "DELETED", borrowerName);
    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}



// --- SEARCH, FILTERS & GENERAL RENDERING ---
function handleSearch() {
    searchQuery = document.getElementById('search-input').value.toLowerCase();
    applyFilters();
}

function filterByStatus(s) {
    currentFilter = s;
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
    if(sessionStorage.getItem('activeRole') === 'admin') {
        updateAnalytics();
    } else if (sessionStorage.getItem('activeRole') === 'student') {
        updateStudentAnalytics();
    }

    let filteredData = vaultData.filter(item => {
        let isNotMaintenance = item.status !== 'Maintenance';
        let matchesStatus = currentFilter === 'All' ? isNotMaintenance : item.status === currentFilter;
        let matchesSearch = item.equipment.toLowerCase().includes(searchQuery);
        return matchesStatus && matchesSearch;
    });

    // NEW: Auto-Sort by Deadline for Borrowed Items
    if (currentFilter === 'Borrowed') {
        filteredData.sort((a, b) => {
            if (!a.returnDate) return 1;
            if (!b.returnDate) return -1;
            return new Date(a.returnDate) - new Date(b.returnDate);
        });
    }

    updateTable(filteredData);
    updateMaintenanceTable(); 
    
    if(!document.getElementById('view-charts').classList.contains('hidden')) updateChart(); 
    if(!document.getElementById('view-requests').classList.contains('hidden')) renderRequestsView();
}

function updateStudentAnalytics() {
    const myName = sessionStorage.getItem('studentName');
    let myBorrowed = 0, myOverdue = 0, myTotalPenalties = 0;

    vaultData.forEach(item => {
        if (item.status === 'Borrowed' && item.borrower === myName) {
            myBorrowed += item.serials ? item.serials.length : 1;
            const targetTime = new Date(item.returnDate + "T23:59:59").getTime();
            
            if (targetTime < new Date().getTime()) {
                myOverdue++;
                const diffDays = Math.ceil((new Date().getTime() - targetTime) / (1000 * 60 * 60 * 24));
                myTotalPenalties += diffDays * 50;
            }
        }
    });

    document.getElementById('student-stat-borrowed').innerText = myBorrowed;
    document.getElementById('student-stat-overdue').innerText = myOverdue;
    document.getElementById('student-stat-penalties').innerText = `₱${myTotalPenalties}`;
}

function updateAnalytics() {
    let totalItems = vaultData.reduce((sum, item) => sum + (item.serials ? item.serials.length : 0), 0);
    document.getElementById('stat-total').innerText = totalItems;
    
    document.getElementById('stat-borrowed').innerText = vaultData.filter(i => i.status === 'Borrowed').reduce((sum, item) => sum + item.serials.length, 0);
    document.getElementById('stat-pending').innerText = vaultData.filter(i => i.status === 'Pending Approval').reduce((sum, item) => sum + item.serials.length, 0);

    let totalPenalties = 0;
    let dueToday = 0;
    let dueTomorrow = 0;
    let itemsOverdue = 0;

    const todayStr = new Date().toISOString().split('T')[0];
    const tomorrowDate = new Date(); tomorrowDate.setDate(tomorrowDate.getDate() + 1);
    const tomorrowStr = tomorrowDate.toISOString().split('T')[0];

    vaultData.forEach(item => {
        if (item.status === 'Borrowed' && item.returnDate) {
            const targetTime = new Date(item.returnDate + "T23:59:59").getTime();
            const now = new Date().getTime();
            if (targetTime < now) {
                itemsOverdue++;
                const diffDays = Math.ceil((now - targetTime) / (1000 * 60 * 60 * 24));
                totalPenalties += diffDays * 50;
            }

            if (item.returnDate === todayStr) dueToday++;
            if (item.returnDate === tomorrowStr) dueTomorrow++;
        }
    });

    document.getElementById('stat-penalties').innerText = `₱${totalPenalties}`;
    
    document.getElementById('stat-due-today').innerText = dueToday;
    document.getElementById('stat-due-tomorrow').innerText = dueTomorrow;
    document.getElementById('stat-overdue').innerText = itemsOverdue;

    const maintItems = vaultData.filter(i => i.status === 'Maintenance');
    document.getElementById('stat-maint-total').innerText = maintItems.length;
    let totalRepairCost = maintItems.reduce((sum, item) => sum + (item.repairCost || 0), 0);
    document.getElementById('stat-maint-cost').innerText = `₱${totalRepairCost}`;
}

// --- CHART GENERATION TOOL ---
function updateChart() {
    if (typeof Chart === 'undefined') return;

    const ctxCat = document.getElementById('categoryChart');
    if (ctxCat) {
        let categoryCounts = {};
        let totalItems = 0;

        vaultData.forEach(item => {
            let cat = item.category || 'Others';
            let qty = item.serials ? item.serials.length : 0;
            if (qty > 0) {
                categoryCounts[cat] = (categoryCounts[cat] || 0) + qty;
                totalItems += qty;
            }
        });

        if (categoryChartInstance) categoryChartInstance.destroy();

        categoryChartInstance = new Chart(ctxCat, {
            type: 'doughnut',
            data: {
                labels: Object.keys(categoryCounts),
                datasets: [{
                    data: Object.values(categoryCounts),
                    backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#64748b'],
                    borderWidth: 2, hoverOffset: 4
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { font: { family: 'Inter', size: 12 } } },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.label || '';
                                if (label) label += ': ';
                                let val = context.parsed;
                                let pct = totalItems > 0 ? ((val / totalItems) * 100).toFixed(1) : 0;
                                return `${label}${val} items (${pct}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    const ctxPop = document.getElementById('popularChart');
    if (ctxPop) {
        let borrowCounts = {};
        
        auditLogs.forEach(log => {
            if (log.action.startsWith("Approved request for ") || log.action.startsWith("Approved batch request ")) {
                let logParts = log.action.split(' for ');
                let detail = logParts.length > 1 ? logParts[1].split(' by ')[0] : log.action;
                borrowCounts[detail] = (borrowCounts[detail] || 0) + 1;
            }
        });

        let sortedPopular = Object.keys(borrowCounts).map(name => {
            return { name: name, count: borrowCounts[name] };
        }).sort((a, b) => b.count - a.count).slice(0, 5);

        if (popularChartInstance) popularChartInstance.destroy();

        popularChartInstance = new Chart(ctxPop, {
            type: 'bar',
            data: {
                labels: sortedPopular.map(i => i.name.length > 15 ? i.name.substring(0,15)+'...' : i.name),
                datasets: [{
                    label: 'Times Borrowed',
                    data: sortedPopular.map(i => i.count),
                    backgroundColor: '#3b82f6',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { title: function(context) { return sortedPopular[context[0].dataIndex].name; } } }
                }
            }
        });
    }
}

// --- TABLE RENDERING: VAULT ---
function updateTable(dataToDisplay, role = sessionStorage.getItem('activeRole'), studentData = {name: sessionStorage.getItem('studentName')}) {
    const thead = document.querySelector('#vault-table thead');
    const list = document.getElementById('inventory-list');
    const isAdmin = (role === 'admin');

    thead.innerHTML = isAdmin ?
        `<tr><th>#</th><th>Equipment</th><th>Category</th><th>Description</th><th>Qty</th><th>Encrypted Serials</th><th>Status</th><th>Action</th></tr>` :
        `<tr><th>#</th><th>Equipment</th><th>Category</th><th>Description</th><th>Qty</th><th>Status</th><th>Action</th></tr>`;

    list.innerHTML = "";
    dataToDisplay.forEach((item, index) => {
        let row = `<tr style="transition: background-color 0.3s;"><td>${index+1}</td><td><strong>${item.equipment}</strong></td>`;
        
        let catHtml = `<td><span style="font-size: 0.8rem; background: #e2e8f0; padding: 4px 8px; border-radius: 6px; color: #475569; white-space: nowrap;">${item.category || 'Others'}</span></td>`;
        let descHtml = `<td>${item.description || '<span style="color:#cbd5e1;font-size:0.8rem;">No Description</span>'}</td>`;
        let qtyHtml = `<td><span style="font-weight:bold; color:var(--cit-blue); background:#e2e8f0; padding:4px 10px; border-radius:20px;">${item.serials ? item.serials.length : 0}</span></td>`;

        let badgeClass = 'badge-available';
        if (item.status === 'Borrowed') badgeClass = 'badge-borrowed';
        if (item.status === 'Pending Approval') badgeClass = 'badge-pending';
        
        // NEW: Visual Progress Bar & Timer Combo
        let penaltyText = "";
        if (item.status === 'Borrowed' && item.returnDate) {
            penaltyText = `
            <div style="background: #e2e8f0; border-radius: 4px; width: 100%; height: 6px; margin-top: 8px; overflow: hidden;">
                <div class="progress-fill" data-date="${item.returnDate}" style="height: 100%; width: 100%; background: #10b981; transition: width 1s linear, background-color 1s;"></div>
            </div>
            <span class="countdown-timer" data-date="${item.returnDate}" style="font-size: 0.75rem; display:inline-block; margin-top:2px;">Calculating...</span>`;
        }
        
        let statusHtml = `<span class="badge ${badgeClass}">${item.status}</span>`;
        if(item.borrower) statusHtml += `<br><small>By: ${item.borrower}</small>`;
        if(item.status === 'Borrowed') statusHtml += penaltyText;

        if (isAdmin) {
            let serialsHtml = '';
            if (!item.serials || item.serials.length === 0) {
                serialsHtml = `<td><span style="color:#cbd5e1;">Empty</span></td>`;
            } else if (item.serials.length === 1) {
                let displaySerial = item.serials[0];
                let shortSerial = displaySerial.length > 15 ? displaySerial.substring(0, 15) + '...' : displaySerial;
                serialsHtml = `<td style="cursor:pointer; font-family:monospace; color:#3b82f6;" title="Click to Decrypt" onclick="unlockItem('${item._id}', 0)">${shortSerial}</td>`;
            } else {
                let options = item.serials.map((s, idx) => {
                    let shortS = s.length > 15 ? s.substring(0, 15) + '...' : s;
                    return `<option value="${idx}">SN #${idx + 1}: ${shortS}</option>`;
                }).join('');
                serialsHtml = `<td>
                    <select id="serial-select-${item._id}" style="width:130px; padding:4px; font-size:0.75rem; border-radius:4px; border:1px solid #cbd5e1; margin-bottom:5px;">${options}</select>
                    <button onclick="unlockSelectedSerial('${item._id}')" class="btn-action-sm" style="background:#3b82f6; padding: 4px; display:block; width:130px;">Decrypt Selected</button>
                </td>`;
            }

            let actionHtml = '';
            if (item.status === 'Pending Approval') {
                actionHtml = `<span style="font-size:0.8rem; color:#64748b;">Check Requests Tab</span>`;
            } else if (item.status === 'Available') {
                actionHtml = `<button onclick="removeItem('${item._id}')" class="btn-delete-row" style="margin-bottom:5px;">Delete</button>
                              <button onclick="openReportModal('${item._id}')" class="btn-action-sm" style="background:#ef4444; color:white;">Report Issue</button>`;
            } else {
                actionHtml = `<button onclick="removeItem('${item._id}')" class="btn-delete-row">Delete Group</button>`;
            }
            
            row += `${catHtml}${descHtml}${qtyHtml}${serialsHtml}
                    <td style="width: 180px;">${statusHtml}</td><td>${actionHtml}</td>`;
        } else {
            let btn = '';
            if (item.status === 'Available') {
                btn = `<button onclick="addToCart('${item._id}')" class="btn-action-sm" style="background:var(--cit-blue); color:white; border:none; padding:6px 8px; border-radius:4px; cursor:pointer; width:100%; margin-bottom:5px; font-weight:bold;">🛒 Add to Bag</button>
                       <button onclick="openReportModal('${item._id}')" class="btn-action-sm" style="background:#ef4444; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer; width:100%;">Report Issue</button>`;
            } else if (item.status === 'Pending Approval' && item.borrower === studentData.name) {
                btn = `<span style="font-size: 0.8rem; color: #6366f1; font-weight: bold;">Waiting...</span>`;
            } else if (item.status === 'Borrowed' && item.borrower === studentData.name) {
                btn = `<button onclick="returnItem('${item._id}')" class="btn-return">Return</button>`;
            } else {
                btn = `<span style="font-size: 0.8rem; color: #64748b;">Unavailable</span>`;
            }
            
            row += `${catHtml}${descHtml}${qtyHtml}<td style="width: 180px;">${statusHtml}</td><td>${btn}</td>`;
        }
        list.innerHTML += row + "</tr>";
    });
}

// --- TABLE RENDERING: MAINTENANCE ---
function updateMaintenanceTable() {
    const list = document.getElementById('maintenance-list');
    const thead = document.querySelector('#maintenance-table thead');
    const isAdmin = (sessionStorage.getItem('activeRole') === 'admin');

    const maintData = vaultData.filter(i => i.status === 'Maintenance');

    thead.innerHTML = isAdmin ?
        `<tr style="border-bottom: 2px solid var(--border); color: var(--text-muted); font-size: 0.85rem;">
            <th style="padding: 12px 10px;">Equipment</th>
            <th style="padding: 12px 10px;">Issue</th>
            <th style="padding: 12px 10px;">Reported By</th>
            <th style="padding: 12px 10px;">Status</th>
            <th style="padding: 12px 10px;">Cost / Sent To</th>
            <th style="padding: 12px 10px;">Est. Return</th>
            <th style="padding: 12px 10px;">Actions</th>
        </tr>` :
        `<tr style="border-bottom: 2px solid var(--border); color: var(--text-muted); font-size: 0.85rem;">
            <th style="padding: 12px 10px;">Equipment</th>
            <th style="padding: 12px 10px;">Issue</th>
            <th style="padding: 12px 10px;">Reported By</th>
            <th style="padding: 12px 10px;">Status</th>
            <th style="padding: 12px 10px;">Est. Return</th>
        </tr>`;

    list.innerHTML = "";
    
    if (maintData.length === 0) {
        list.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:#64748b;">No items currently under maintenance.</td></tr>`;
        return;
    }

    maintData.forEach(item => {
        let badgeColor = '#64748b'; 
        let rs = item.repairStatus || 'Pending';
        if (rs === 'Pending' || rs === 'Diagnosed') badgeColor = '#ef4444'; 
        else if (rs === 'Sent for Repair' || rs === 'Repairing') badgeColor = '#f59e0b'; 
        else if (rs === 'Fixed') badgeColor = '#10b981'; 

        let statusBadge = `<span style="background:${badgeColor}; color:white; padding:4px 8px; border-radius:12px; font-size:0.75rem; font-weight:bold;">${rs}</span>`;
        let returnText = item.estimatedReturnDate ? `<small style="color:#64748b;">${item.estimatedReturnDate}</small>` : `<small style="color:#cbd5e1;">Not Set</small>`;

        let row = `<tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 12px 10px;"><strong>${item.equipment}</strong><br><small style="color:#64748b;">${item.category || ''}</small></td>
            <td style="padding: 12px 10px; max-width: 200px;"><small>${item.issueDescription || 'No description'}</small></td>
            <td style="padding: 12px 10px;"><small><strong>${item.reportedBy || 'System'}</strong><br>${item.dateReported || ''}</small></td>
            <td style="padding: 12px 10px;">${statusBadge}</td>`;

        if (isAdmin) {
            let details = `<small style="color:#64748b;">₱${item.repairCost || 0}<br>${item.sentTo || 'Internal'}</small>`;
            
            let actionHtml = `
                <button onclick="openEditMaintModal('${item._id}')" class="btn-action-sm" style="background:#3b82f6; width:100%; margin-bottom:5px;">Edit Record</button>
                <button onclick="markAsFixed('${item._id}')" class="btn-action-sm" style="background:#10b981; width:100%;">Mark Fixed (Return)</button>
            `;
            
            row += `<td style="padding: 12px 10px;">${details}</td><td style="padding: 12px 10px;">${returnText}</td><td style="padding: 12px 10px;">${actionHtml}</td>`;
        } else {
            row += `<td style="padding: 12px 10px;">${returnText}</td>`;
        }
        
        row += `</tr>`;
        list.innerHTML += row;
    });
}


// --- DATABASE ACTIONS ---
async function addNewItem() {
    const n = document.getElementById('item-name').value.trim();
    const s = document.getElementById('item-serial').value.trim();
    const desc = document.getElementById('item-description').value.trim(); 
    const price = document.getElementById('item-price').value.trim();      
    const cat = document.getElementById('item-category').value; 

    if (!n || !s || !desc || !price || !cat) { 
        alert("Action Denied: Name, Serial, Description, Price, and Category are required."); 
        return; 
    }

    const encryptedSerial = await apply3DESWithVisuals(s);
    const existingItem = vaultData.find(i => i.equipment.toLowerCase() === n.toLowerCase() && i.status === 'Available');

    if (existingItem) {
        existingItem.serials.push(encryptedSerial);
        try {
            await fetch(`${API_URL}/items/${existingItem._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(existingItem) });
            addLog(`Combined Serial into existing group: ${n}`, "SUCCESS", "admin");
        } catch(err) { console.error(err); return; }
    } else {
        const newItem = { equipment: n, category: cat, description: desc, price: Number(price), serials: [encryptedSerial], status: 'Available' };
        try {
            await fetch(`${API_URL}/items`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newItem) });
            addLog(`Registered New Item Group: ${n}`, "SUCCESS", "admin");
        } catch(err) { console.error(err); return; }
    }

    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();

    document.getElementById('item-name').value = "";
    document.getElementById('item-serial').value = "";
    document.getElementById('item-description').value = ""; 
    document.getElementById('item-price').value = "";       
    document.getElementById('item-category').value = ""; 
    applyFilters(); 
}

// --- MAINTENANCE ACTIONS ---
function openReportModal(id) {
    pendingReportId = id;
    const item = vaultData.find(i => i._id === id);
    const selContainer = document.getElementById('report-serial-container');
    const selectEl = document.getElementById('report-serial-select');
    
    document.getElementById('report-issue-desc').value = "";

    if (item.serials && item.serials.length > 1) {
        selContainer.classList.remove('hidden');
        selectEl.innerHTML = item.serials.map((s, idx) => {
            let shortS = s.length > 15 ? s.substring(0, 15) + '...' : s;
            return `<option value="${idx}">SN #${idx + 1}: ${shortS}</option>`;
        }).join('');
    } else {
        selContainer.classList.add('hidden');
        selectEl.innerHTML = `<option value="0">Default</option>`;
    }
    
    document.getElementById('report-modal').classList.remove('hidden');
}

function closeReportModal() {
    document.getElementById('report-modal').classList.add('hidden');
}

async function submitBrokenReport() {
    const desc = document.getElementById('report-issue-desc').value.trim();
    if (!desc) return alert("Please provide a description of the issue.");
    
    let item = vaultData.find(i => i._id === pendingReportId);
    let selectedIdx = parseInt(document.getElementById('report-serial-select').value) || 0;
    
    let reporter = sessionStorage.getItem('activeRole') === 'admin' ? 'Admin' : sessionStorage.getItem('studentName');
    let today = new Date().toLocaleDateString();

    if (item.serials.length > 1) {
        const brokenSerial = item.serials.splice(selectedIdx, 1)[0]; 
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });

        const brokenItemObj = {
            equipment: item.equipment, category: item.category, description: item.description, price: item.price, serials: [brokenSerial],
            status: 'Maintenance', repairStatus: 'Pending', issueDescription: desc, reportedBy: reporter, dateReported: today
        };

        await fetch(`${API_URL}/items`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(brokenItemObj) });
    } else {
        item.status = 'Maintenance';
        item.repairStatus = 'Pending';
        item.issueDescription = desc;
        item.reportedBy = reporter;
        item.dateReported = today;

        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
    }

    addLog(`Reported broken: ${item.equipment}`, "PENDING", reporter);
    closeReportModal();
    
    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}

function openEditMaintModal(id) {
    pendingMaintenanceId = id;
    const item = vaultData.find(i => i._id === id);
    
    document.getElementById('edit-maint-eq-name').innerText = `Editing: ${item.equipment}`;
    document.getElementById('maint-status').value = item.repairStatus || 'Pending';
    document.getElementById('maint-sent-to').value = item.sentTo || '';
    document.getElementById('maint-cost').value = item.repairCost || '';
    document.getElementById('maint-return-date').value = item.estimatedReturnDate || '';
    document.getElementById('maint-notes').value = item.maintenanceNotes || '';
    
    document.getElementById('edit-maintenance-modal').classList.remove('hidden');
}

function closeEditMaintModal() {
    document.getElementById('edit-maintenance-modal').classList.add('hidden');
}

async function saveMaintenanceUpdate() {
    let item = vaultData.find(i => i._id === pendingMaintenanceId);
    
    item.repairStatus = document.getElementById('maint-status').value;
    item.sentTo = document.getElementById('maint-sent-to').value;
    item.repairCost = Number(document.getElementById('maint-cost').value);
    item.estimatedReturnDate = document.getElementById('maint-return-date').value;
    item.maintenanceNotes = document.getElementById('maint-notes').value;

    try {
        await fetch(`${API_URL}/items/${item._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(item) });
        addLog(`Updated repair record: ${item.equipment} (${item.repairStatus})`, "SUCCESS", "admin");
        closeEditMaintModal();
        
        const itemsRes = await fetch(`${API_URL}/items`);
        vaultData = await itemsRes.json();
        applyFilters();
    } catch(err) { console.error(err); }
}

async function markAsFixed(id) {
    if(!confirm("Is this item fixed? It will be returned to the Available Vault.")) return;

    let repairedItem = vaultData.find(i => i._id === id);
    const existingAvailableGroup = vaultData.find(i => i.equipment.toLowerCase() === repairedItem.equipment.toLowerCase() && i.status === 'Available' && i._id !== id);

    if (existingAvailableGroup) {
        existingAvailableGroup.serials.push(repairedItem.serials[0]);
        await fetch(`${API_URL}/items/${existingAvailableGroup._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(existingAvailableGroup) });
        await fetch(`${API_URL}/items/${id}`, { method: 'DELETE' });
    } else {
        repairedItem.status = 'Available'; 
        repairedItem.repairStatus = '';
        repairedItem.issueDescription = '';
        repairedItem.reportedBy = '';
        repairedItem.dateReported = '';
        repairedItem.sentTo = '';
        repairedItem.repairCost = 0;
        repairedItem.estimatedReturnDate = '';
        repairedItem.maintenanceNotes = '';

        await fetch(`${API_URL}/items/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(repairedItem) });
    }

    addLog(`Fixed & Returned to Vault: ${repairedItem.equipment}`, "SUCCESS", "admin");
    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}

// --- UTILS & RETURNS ---
function unlockItem(id, index = 0) {
    const item = vaultData.find(i => i._id === id);
    const decryptedSerial = decrypt3DES(item.serials[index]);
    addLog(`Decrypted ${item.equipment}`, "SUCCESS", "admin");
    alert(`🔓 Original Serial: ${decryptedSerial}`);
}

function unlockSelectedSerial(id) {
    const item = vaultData.find(i => i._id === id);
    const selectEl = document.getElementById(`serial-select-${id}`);
    const selectedIndex = selectEl.value;
    const decryptedSerial = decrypt3DES(item.serials[selectedIndex]);
    addLog(`Decrypted ${item.equipment} (Serial #${parseInt(selectedIndex) + 1})`, "SUCCESS", "admin");
    alert(`🔓 Original Serial: ${decryptedSerial}`);
}

async function removeItem(id) {
    if(confirm("Delete this entire group of items?")) {
        await fetch(`${API_URL}/items/${id}`, { method: 'DELETE' });
        vaultData = vaultData.filter(i => i._id !== id);
        applyFilters();
    }
}

async function returnItem(id) {
    let returnedItem = vaultData.find(i => i._id === id);
    
    addLog(`Returned ${returnedItem.equipment}`, "SUCCESS", returnedItem.borrower);
    
    const existingAvailableGroup = vaultData.find(i => i.equipment.toLowerCase() === returnedItem.equipment.toLowerCase() && i.status === 'Available' && i._id !== id);

    if (existingAvailableGroup) {
        existingAvailableGroup.serials.push(returnedItem.serials[0]);
        await fetch(`${API_URL}/items/${existingAvailableGroup._id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(existingAvailableGroup) });
        await fetch(`${API_URL}/items/${id}`, { method: 'DELETE' });
    } else {
        returnedItem.status = 'Available'; returnedItem.borrower = ''; returnedItem.returnDate = '';
        returnedItem.transactionId = ''; returnedItem.purpose = '';
        await fetch(`${API_URL}/items/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(returnedItem) });
    }

    const itemsRes = await fetch(`${API_URL}/items`);
    vaultData = await itemsRes.json();
    applyFilters();
}

async function saveNewPassword() {
    const oldPass = document.getElementById('old-password-field').value;
    const newPass = document.getElementById('new-password-field').value;
    if (!oldPass || !newPass) { alert("Please fill in both fields."); return; }

    if (oldPass === currentPassword) {
        currentPassword = newPass;
        await fetch(`${API_URL}/config`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin: currentPassword }) });
        addLog("Admin Password Changed", "SUCCESS", "admin"); 
        alert("Password Updated!"); closePasswordModal();
    } else {
        addLog("Failed Password Update Attempt", "SECURITY ALERT", "admin"); alert("Incorrect Old Password.");
    }
}

function closeAlert() { document.getElementById('security-alert').classList.add('hidden'); }
function openPasswordModal() { document.getElementById('password-modal').classList.remove('hidden'); }
function closePasswordModal() { document.getElementById('password-modal').classList.add('hidden'); }
function handleLoginEnter(e) { if(e.key === 'Enter') checkAdminLogin(); }
function handleAddItemEnter(e) { if(e.key === 'Enter') addNewItem(); }
function handleUpdatePasswordEnter(e) { if(e.key === 'Enter') { e.preventDefault(); saveNewPassword(); } }

window.onscroll = function() { toggleScrollButton() };
function toggleScrollButton() {
    const btn = document.getElementById("scroll-top-btn");
    btn.style.display = (document.body.scrollTop > 200 || document.documentElement.scrollTop > 200) ? "block" : "none";
}
function scrollToTop() { window.scrollTo({ top: 0, behavior: 'smooth' }); }