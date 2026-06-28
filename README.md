# Shadow Scan 

Outil d'audit de sécurité (Rust / Debian).

##  Installation
```bash
git clone [https://github.com/goated2323/shadow_scan.git](https://github.com/goated2323/shadow_scan.git)
cd shadow_scan
sudo dpkg -i shadow-scan-pkg.deb
sudo apt-get install -f
utilisation shadow_scan
Binaire : /usr/local/bin/shadow-scan

Output : rapport_audit.json

Arborescence :

    src/main.rs (Source code)

    Cargo.toml (Manifest)

    shadow-scan-pkg/ (Debian structure)
