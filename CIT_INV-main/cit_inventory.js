const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');

// ==========================================
// 1. Algorithm & Persistent Key Generation
// ==========================================
const algorithm = 'des-ede3-cbc';
const masterKey = crypto.scryptSync('Group8_CIT_SuperSecret', 'salt', 24);
const iv = Buffer.alloc(8, 0);

// ==========================================
// 2. Data Protection: File Storage & PIN
// ==========================================
const DB_FILE = 'cit_vault.json';
const PIN_FILE = 'cit_pin.txt';

let inventoryDatabase = [];
let adminPin = '1234'; // Default PIN

if (fs.existsSync(DB_FILE)) {
    const rawData = fs.readFileSync(DB_FILE, 'utf8');
    inventoryDatabase = JSON.parse(rawData);
}

if (fs.existsSync(PIN_FILE)) {
    adminPin = fs.readFileSync(PIN_FILE, 'utf8').trim();
}

function saveDatabase() {
    fs.writeFileSync(DB_FILE, JSON.stringify(inventoryDatabase, null, 4));
}

function savePin(newPin) {
    adminPin = newPin;
    fs.writeFileSync(PIN_FILE, adminPin);
}

// ==========================================
// 3. 3DES Encryption & Decryption
// ==========================================
function encryptData(plainText) {
    const cipher = crypto.createCipheriv(algorithm, masterKey, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(encryptedHex) {
    const decipher = crypto.createDecipheriv(algorithm, masterKey, iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==========================================
// MAIN PROGRAM: Interactive Terminal UI
// ==========================================
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function systemLogin() {
    console.log("\n=================================================");
    console.log("  CIT Laboratory Equipment Inventory Security");
    console.log("=================================================\n");
    console.log(`[*] 3DES Master Key Loaded.`);
    console.log(`[*] Secure Vault contains ${inventoryDatabase.length} encrypted items.\n`);
    
    rl.question("Enter Administrative Access PIN: ", function(pin) {
        
        // Correct PIN check
        if (pin === adminPin) {
            console.log("\n[UNLOCK] Access Granted. Welcome, Administrator.");
            askForCommand();
        } 
        // Any other input (Wrong PIN or Blank) triggers the warning
        else {
            console.log("\n===================================================");
            console.log("             AUTHORIZED PERSONNEL ONLY             ");
            console.log("===================================================");
            console.log("[!] ACCESS DENIED. Unauthorized attempt detected.\n");
            systemLogin(); // Loop back to login
        }
    });
}

function askForCommand() {
    console.log("\nCOMMANDS: [add] Equipment | [list] Inventory | [del] Equipment | [changepin] | [exit]");

    rl.question("Enter command: ", function(input) {
        const command = input.trim().toLowerCase();

        if (command === 'exit') {
            console.log("Locking vault and closing system. Goodbye!\n");
            rl.close();
            return;
        }

        if (command === 'add') {
            rl.question("Enter new lab equipment name: ", function(equipmentName) {
                rl.question(`Enter sensitive Serial Number for ${equipmentName}: `, function(serialNumber) {
                    console.log("\n--- Processing 3DES Encryption ---");
                    const encryptedSerial = encryptData(serialNumber);
                    
                    inventoryDatabase.push({
                        id: Date.now(),
                        name: equipmentName,
                        encryptedSerial: encryptedSerial
                    });
                    saveDatabase(); 
                    
                    console.log(`[LOCK] Saved! Encrypted Serial: ${encryptedSerial}`);
                    askForCommand();
                });
            });
            return;
        }

        if (command === 'del' || command === 'delete') {
            rl.question("Enter the Item Number (1, 2, 3...) to delete: ", function(numStr) {
                const index = parseInt(numStr) - 1;
                if (index >= 0 && index < inventoryDatabase.length) {
                    const removed = inventoryDatabase.splice(index, 1);
                    saveDatabase();
                    console.log(`[*] Successfully deleted '${removed[0].name}'.`);
                } else {
                    console.log("[!] Invalid Item Number.");
                }
                askForCommand();
            });
            return;
        }

        if (command === 'changepin') {
            rl.question("Enter NEW Admin PIN: ", function(newPin) {
                savePin(newPin);
                console.log("\n[*] SUCCESS: Admin PIN has been updated securely.");
                askForCommand();
            });
            return;
        }

        if (command === 'list') {
            if (inventoryDatabase.length === 0) {
                console.log("\nThe vault is currently empty.");
            } else {
                console.log("\n========== SECURE CIT INVENTORY DATABASE ==========");
                inventoryDatabase.forEach((item, index) => {
                    const decryptedSerial = decryptData(item.encryptedSerial);
                    console.log(`${index + 1}. Equipment: ${item.name}`);
                    console.log(`   [Serial Number]: ${decryptedSerial}\n`);
                });
                console.log("===================================================");
            }
            askForCommand();
            return;
        }

        console.log("[!] Invalid command.");
        askForCommand();
    });
}

// Start the application
systemLogin();