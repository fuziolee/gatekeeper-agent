# Gatekeeper — Runbook 16:00 WIB, Minggu 15 Nov 2026

Tujuan: ikut **Ronde 3 Proof Gatekeeper, buka 17:30 WIB** (pendaftaran dikunci
saat ronde dibuka). User kembali on jam **16:00 WIB** — ada 90 menit.

## Status terverifikasi pagi ini (15 Nov 07:11 WIB)

- Server Gatekeeper **sehat**: `GET /health` jawab
  `{"ok":true,"service":"gatekeeper-agent","protocolVersion":"v1","mode":"dev-unsigned"}`.
  Mode dev-unsigned itu wajar — secret HMAC baru ada setelah "Rotate Secret"
  di dashboard jam 16:00 nanti.
- Repo di `~/workspace/zkv-gatekeeper/`, commit `7184960`, 20 file, tes 17/17
  lolos, simulasi platform 10/10. **Belum ada git remote** — repo belum di-push
  ke GitHub (butuh browser + kode dari user, seperti proof-buddy kemarin).
- **KOREKSI 15 Nov 11:35 WIB — tidak ada tunnel yang jalan dari VM ini.**
  Dicek ulang pagi ini (bukan cuma API-nya): `api.ngrok.com` dan
  `api.cloudflare.com` memang menjawab (400), TAPI itu cuma management API —
  bukan jalur tunnel-nya. Yang diuji langsung:
  - **ngrok v3.39.13** (binary berhasil diunduh): agent gagal
    `failed to send authentication request: EOF`, dengan maupun tanpa
    authtoken (diuji pakai token placeholder 11:34 WIB); curl ke
    `connect.ngrok-agent.com` / `tunnel.ngrok.com` = 000,
    `update.ngrok-agent.com` = 403. **ngrok TERBLOKIR dari VM.**
  - **cloudflared 2025.10.0** (binary berhasil diunduh): quick tunnel gagal
    (`api.trycloudflare.com` diblokir); named tunnel juga (hampir pasti)
    gagal — `region1/region2.argotunnel.com` tidak menjawab (curl 000,
    timeout 10 dtk). TCP 443 ke semua host ini tersambung (proxy yang
    menjawab), tapi TLS-nya diputus. **Cloudflare Tunnel TERBLOKIR dari VM.**
  - `scripts/start.sh` di repo ini hanya menjalankan localtunnel — itu juga
    sudah terbukti mati dari VM. Jadi **laptop Windows user adalah
    satu-satunya jalan yang bisa diandalkan**; token ngrok/Cloudflare hanya
    berguna kalau dijalankan di laptop atau host lain dengan egress langsung.

## Yang perlu user siapkan SEBELUM 16:00 (biar 90 menit tidak habis)

Pilih satu saja — **laptop adalah rencana utama** (satu-satunya yang terbukti
bisa; ngrok/Cloudflare sudah diuji dan terblokir dari VM ini):

1. **Laptop Windows (rencana utama, paling bisa diandalkan)** — install
   **Node.js LTS** (v22+) dan **Git for Windows** (sekalian dapat Git Bash),
   biarkan laptop nyala + Chrome terbuka selama ronde (17:30–03:30 WIB).
   Di laptop, `scripts/start.sh` memakai localtunnel subdomain tetap
   `gatekeeper-fuziole.loca.lt` — dari laptop dengan egress langsung itu
   seharusnya jalan.
2. **ngrok / Cloudflare — HANYA kalau dijalankan di laptop**, bukan di VM:
   daftar gratis ngrok.com (authtoken) atau siapkan API token Cloudflare
   (izin tunnel). Jangan buang waktu mencoba token ini di VM — sudah diuji
   11:35 WIB dan jalurnya diputus proxy.

## Rencana 16:00–17:30 WIB

| Jam | Langkah |
|---|---|
| 16:00–16:10 | Pilih endpoint — rencana utama **laptop Windows** (ngrok/Cloudflare dari VM sudah terbukti terblokir, jangan dicoba lagi). |
| 16:10–16:30 | Push repo Gatekeeper ke GitHub `fuziolee` (publik) — butuh browser + kode verifikasi dari user. Ambil URL repo publiknya. |
| 16:30–16:50 | Daftar agen di dashboard Agent Games: nama, centang Gatekeeper, URL repo, endpoint `https://<tunnel>/agent`. Lalu **Rotate Secret** → salin secret sekali-tampil itu ke `.env` sebagai `AGENT_GAMES_HMAC_SECRET` → restart server (`scripts/start.sh stop && scripts/start.sh`). |
| 16:50–17:10 | Preflight dari dashboard (agen harus jawab `{ok:true, protocolVersion:"v1"}`), lalu 1 practice task; cek log server ada `decision=… reason=… proof=yes`. |
| 17:10–17:30 | Buffer. Pastikan agen tampil aktif sebelum 17:30. |

Perintah laptop (di Git Bash, di folder repo hasil clone):

```bash
npm install
npm test            # harus 17/17 lolos
cp .env.example .env   # isi AGENT_GAMES_HMAC_SECRET hasil Rotate Secret
scripts/start.sh    # server di 127.0.0.1:8788 + tunnel, URL publik tercetak
```

Di laptop, `scripts/start.sh` memakai localtunnel subdomain tetap
`gatekeeper-fuziole.loca.lt` — URL `https://gatekeeper-fuziole.loca.lt/agent`
itu yang didaftarkan, dan tetap sama kalau tunnel di-restart.

## Kalau tidak sempat jam 17:30 — jangan dipaksa

Ronde 3 bukan satu-satunya: ronde harian 13–20 Nov, jadi **Ronde 4 besok
16 Nov 17:30 WIB** masih ada (lalu Ronde 5–8). Kalau endpoint belum siap
sekitar 17:15, lebih baik daftarkan dengan tenang untuk Ronde 4 daripada
daftar setengah jadi dan gagal preflight. Konteks klasemen: per 15 Nov
00:04 WIB, #1 di 104 poin, enam agen di 80 poin setelah 2 ronde — mengejar
dari Ronde 3 butuh nyaris sempurna (8 tugas × 12 poin per ronde), dari
Ronde 4 lebih berat lagi, tapi tetap mungkin.

## Yang TIDAK perlu diurus hari ini

- Wildcard ProofBuddy + 2 entri Creator (thread + artikel): ketiganya sudah
  **PENDING** review manual — tidak ada aksi.
- Steal the VFY: tertutup untuk pendaftar baru. make.fun: dihentikan user.
- Syarat kelayakan hadiah ke-5 masih belum diketahui (4 dari 5 terpenuhi).
