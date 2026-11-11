# Gopin Semicon Private Limited — ERP

Apne server aur apne database par chalne wala manufacturing ERP.

**Modules**
- Masters (Excel/CSV import-export ke saath): Items, Suppliers, Customers, Warehouses, BOM, Routings, Work Centers, Units
- Purchase Order → GRN (QC accept/reject) → Purchase Invoice
- Production Orders: material issue, finished goods receipt, routing aur machine schedule
- Sales Order → Dispatch → GST Tax Invoice (CGST/SGST/IGST, print)
- Inventory: Stock on hand, Batch / lot aur aging, Stock ledger, Stock journal, Material planning
- Gate Pass: Inward / RGP / NRGP
- Users & Roles: login, approvals, audit history

**Live updates:** Jab koi bhi user entry save karta hai, wo baaki sab logged-in users ki screen par turant aa jaati hai (WebSocket se). Refresh karne ki zaroorat nahi.

---

## 1. Kya chahiye

| | Minimum |
|---|---|
| Server | Ubuntu 22.04 / 24.04 VPS, 2 GB RAM, 20 GB disk (AWS Lightsail, DigitalOcean, Hostinger VPS, E2E Networks — koi bhi) |
| Domain | Ek subdomain, jaise `erp.gopinsemicon.com` (HTTPS ke liye) |
| Software | Docker + Docker Compose (Step 3 mein install hota hai) |

Sirf office ke andar (LAN par) chalana ho to koi bhi Windows/Linux PC jisme Docker Desktop ho, wo bhi chalega. Section 6 dekhein.

---

## 2. Pehle apne PC par test karein (optional, 10 minute)

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) install karein.
2. Is folder mein `.env.example` ko copy karke `.env` naam dein.
3. `.env` file kholkar ye 4 cheezein badlein:
   - `JWT_SECRET`
   - `POSTGRES_PASSWORD`
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
4. Is folder mein terminal kholkar chalayein:
   ```
   docker compose up -d --build
   ```
5. Browser mein `http://localhost:3000` kholein aur `ADMIN_EMAIL` / `ADMIN_PASSWORD` se sign in karein.

---

## 3. Live server par setup (Ubuntu VPS)

### 3.1 Server taiyar karein
```bash
ssh root@YOUR_SERVER_IP
apt update && apt -y upgrade
curl -fsSL https://get.docker.com | sh
apt -y install nginx certbot python3-certbot-nginx
ufw allow OpenSSH && ufw allow 'Nginx Full' && ufw --force enable
```

### 3.2 Project upload karein
Apne PC se zip upload karke server par unzip karein:
```bash
# PC par (PowerShell / terminal):
scp gopin-erp.zip root@YOUR_SERVER_IP:/opt/

# Server par:
cd /opt && apt -y install unzip && unzip gopin-erp.zip && cd gopin-erp
```

### 3.3 Settings
```bash
cp .env.example .env
openssl rand -hex 32        # is output ko JWT_SECRET mein daalein
nano .env
```
`.env` mein ye values set karein:
- `JWT_SECRET`
- `POSTGRES_PASSWORD`: strong password
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`: aapka pehla Admin login
- `COOKIE_SECURE=true`
- `TRUST_PROXY=true`

Save karne ke liye `Ctrl+O`, `Enter`, phir `Ctrl+X` dabayein.

### 3.4 App start karein
```bash
docker compose up -d --build
docker compose logs -f app      # "ERP running" dikhe to Ctrl+C dabayein
```

### 3.5 Domain aur HTTPS
1. Apne domain provider (GoDaddy, Hostinger, etc.) mein **A record** banayein: `erp` → `YOUR_SERVER_IP`.
2. Server par Nginx set karein:
   ```bash
   sed -i 's/erp.gopinsemicon.com/erp.YOURDOMAIN.com/g' deploy/nginx-erp.conf
   cp deploy/nginx-erp.conf /etc/nginx/sites-available/erp
   ln -s /etc/nginx/sites-available/erp /etc/nginx/sites-enabled/erp
   nginx -t && systemctl reload nginx
   certbot --nginx -d erp.YOURDOMAIN.com
   ```
3. Ab `https://erp.YOURDOMAIN.com` kholein. ERP live hai.

### 3.6 Daily backup (zaroor karein)
```bash
chmod +x deploy/backup.sh
mkdir -p backups
crontab -e
```
`crontab -e` khulne par ye line add karein:
```
30 1 * * * /opt/gopin-erp/deploy/backup.sh >> /opt/gopin-erp/backups/backup.log 2>&1
```
- Ye roz raat 1:30 baje database ka backup `backups/` folder mein save karega aur 30 din tak rakhega.
- Backup files ko kabhi-kabhi server se bahar bhi copy karte rahein (Google Drive / PC).
- Iske alawa ERP mein **Company Setup → Download full backup (JSON)** se bhi backup le sakte hain.

---

## 4. Pehli baar ERP mein

1. Admin se sign in karein.
2. **Company Setup** bharein: GSTIN, State (GST ke liye zaroori), shift time, PO approval limit, bank details.
3. **Users & Roles** mein har team member ka user banayein: naam, email, temporary password aur role.
4. Masters ko Excel se import karein. Har list mein **Export ▾ → Blank import template** se sahi columns wali sheet milti hai.
5. Opening stock **Stock Journal** (reason: Opening Stock) se daalein.

---

## 5. Roz ke kaam

| Kaam | Command (server par `/opt/gopin-erp` folder mein) |
|---|---|
| Status dekhna | `docker compose ps` |
| Logs dekhna | `docker compose logs -f app` |
| Restart | `docker compose restart app` |
| Naya version daalna | Nayi files copy karein → `docker compose up -d --build` (data safe rehta hai) |
| Admin password bhool gaye | `docker compose exec app npm run create-admin -- --email you@co.com --name "Name" --password "NewPass123"` |
| SQL backup se restore | `gunzip -c backups/FILE.sql.gz \| docker compose exec -T db psql -U gopin gopin_erp` |
| JSON backup se restore | File ko folder mein rakhein → `docker compose exec app npm run restore -- backup.json` |

**Data kahan hai?** Docker volume `gopin-erp_pgdata` mein. `docker compose down` se data delete nahi hota. Sirf `docker compose down -v` se delete hota hai, isliye wo command kabhi na chalayein.

---

## 6. Sirf office LAN par (bina domain ke)

- `docker-compose.yml` mein `"127.0.0.1:${PORT:-3000}:${PORT:-3000}"` ko badalkar `"3000:3000"` karein.
- `.env` mein `COOKIE_SECURE=false` rakhein.
- Office ke dusre PC browser mein `http://SERVER-PC-IP:3000` kholein.
- Ise internet par bina HTTPS ke na kholein.

---

## 7. Bina Docker ke (advanced)

1. Node.js 20 aur PostgreSQL 16 install karein.
2. Database banayein:
   ```bash
   sudo -u postgres psql -c "CREATE USER gopin WITH PASSWORD 'pass';" -c "CREATE DATABASE gopin_erp OWNER gopin;"
   ```
3. Project ko `/opt/gopin-erp` mein rakhein.
4. `.env` mein `DATABASE_URL=postgres://gopin:pass@localhost:5432/gopin_erp` set karein.
5. Dependencies install karein:
   ```bash
   npm install --omit=dev
   ```
6. Service chalu karein:
   ```bash
   cp deploy/gopin-erp.service /etc/systemd/system/
   chown -R www-data /opt/gopin-erp
   systemctl enable --now gopin-erp
   ```
7. Nginx ke liye Section 3.5 follow karein.

---

## 8. Security

- **Login:**
  - Password bcrypt se encrypted save hote hain.
  - Session cookie httpOnly hoti hai aur 12 ghante mein expire hoti hai.
  - 15 minute mein 10 galat attempts ke baad login block ho jaata hai.
- **Users:** User ko deactivate karne ya uska password reset karne par wo turant har device se sign out ho jaata hai.
- **Server par role checks:**
  - Server khud check karta hai ki kaunsa role kaunsa data badal sakta hai (`roles.js`).
  - Viewer kuch save nahi kar sakta.
  - Users aur Company Setup sirf Admin badal sakta hai.
- **Approval steps:** Approve/Post jaise steps abhi app (browser) mein check hote hain. Server par status-level checks agla upgrade ho sakta hai.
- **Audit:** Har save/delete database ki `audit` table mein user aur time ke saath record hota hai.
- **Zaroori:** `.env` file kisi ko na dein aur GitHub par na daalein.

---

## 9. Mobile app

ERP ek installable app (PWA) hai. Phone par ye home screen icon se full screen mein khulta hai, aur entries live update hoti hain.

> Install sirf **https://** wale live domain par hota hai (Section 3.5). `localhost` par sirf computer mein test hota hai.

**Android (Chrome)**
1. `https://erp.YOURDOMAIN.com` kholein aur sign in karein.
2. Upar **Install app** button dabayein. Ya Chrome menu ⋮ → **Install app / Add to Home screen** chunein.
3. Home screen par **Gopin ERP** icon aa jaayega. Icon ko long-press karne par shortcuts milte hain: GRN, Dispatch, Gate Pass, Stock.

**iPhone / iPad (Safari)**
1. Safari mein ERP kholein.
2. **Share** (square + arrow) → **Add to Home Screen** → **Add** dabayein.

**Kaise kaam karta hai**
- App update apne aap aate hain. Server par naya version daalte hi agli baar app kholne par naya version khul jaata hai.
- Data hamesha server se live aata hai, phone par save nahi hota.
- Phone background se wapas aate hi app turant latest data le aata hai.
- Bina internet ke app khulega, lekin entry save nahi hogi. "Server not reachable" dikhega.

**Google Play Store par daalna (optional)**
1. [PWABuilder.com](https://www.pwabuilder.com) par apna ERP URL daalein → **Package for stores → Android** chunein.
2. Wahan se download hue zip mein `assetlinks.json` hogi. Use server par `public/.well-known/assetlinks.json` mein rakhein, phir `docker compose up -d --build` chalayein.
3. `.aab` file ko Google Play Console mein upload karein. Isme ek baar ki $25 developer fee lagti hai.
4. Company ke internal use ke liye Play Store zaroori nahi hai. Upar wala Install tarika kaafi hai.

## 10. Project structure

```
server.js          API, login, live updates (WebSocket)
roles.js           Role → module permissions (server side)
db.js, schema.sql  PostgreSQL connection and tables
public/index.html  ERP screen (sab modules)
public/manifest.webmanifest, sw.js, icons/   Mobile app (PWA) files
scripts/           create-admin, restore
deploy/            nginx config, backup script, systemd service
```

**Data model:**
- Har record `docs` table mein JSON ke roop mein save hota hai. `collection` ka matlab hai record kis module ka hai (items, pos, grns, ledger…), aur `id` uska code ya number.
- Isse naye fields ya modules jodna aasaan hai.
- Reporting ya Power BI ke liye PostgreSQL views bana sakte hain, jaise:
  ```sql
  SELECT data->>'code' AS code, data->>'name' AS name FROM docs WHERE collection='items';
  ```

## 11. Next level ke ideas

- E-invoice (IRN) aur e-way bill API integration
- Server-side approval rules aur multi-level approval
- Email/WhatsApp alerts (PO approval, RGP overdue, low stock)
- Quality module (incoming / in-process inspection, NCR)
- Maintenance (machine breakdown, preventive maintenance schedule)
- HR / attendance link
- Accounts (payments, receivables, ledger), Power BI dashboards
- Mobile app (PWA) aur barcode/QR scanning
