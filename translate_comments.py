#!/usr/bin/env python3
"""
Script to translate Italian comments and strings to English
"""

import os
import re


def translate_file(file_path):
    """Translate Italian comments and strings in a Python file"""

    translations = {
        # Comments
        "# Crea": "# Create",
        "# Controlla": "# Check",
        "# Aggiunge": "# Add",
        "# Salva": "# Save",
        "# Recupera": "# Retrieve",
        "# Estrae": "# Extract",
        "# Parsa": "# Parse",
        "# Rimuove": "# Remove",
        "# Genera": "# Generate",
        "# Configura": "# Configure",
        "# Inizializza": "# Initialize",
        "# Applica": "# Apply",
        "# Verifica": "# Verify",
        "# Costruisce": "# Build",
        # Docstrings and messages
        "Recupera i CVE recenti": "Retrieve recent CVEs",
        "Controlla le vulnerabilità": "Check vulnerabilities",
        "Cerca CVE per": "Search CVEs for",
        "Salva un CVE": "Save a CVE",
        "nel database": "in the database",
        "dall'API NIST": "from NIST API",
        "per un prodotto": "for a product",
        "degli asset": "of assets",
        "dell'utente": "of the user",
        "Errore nel": "Error in",
        "Errore nella": "Error in",
        "Impossibile": "Unable to",
        "recupero dei": "retrieving",
        "recupero CVE": "CVE retrieval",
        "ricerca CVE": "CVE search",
        "controllo delle": "checking",
        "controllo vulnerabilità": "vulnerability check",
        "Asset già": "Asset already",
        "Asset creato": "Asset created",
        "Asset aggiornato": "Asset updated",
        "Asset eliminato": "Asset deleted",
        "Utente già": "User already",
        "Utente registrato": "User registered",
        "Login effettuato": "Login successful",
        "Login fallito": "Login failed",
        "Autenticazione": "Authentication",
        "Autorizzazione": "Authorization",
        "Token non valido": "Invalid token",
        "Credenziali": "Credentials",
        "Password": "Password",
        "Email": "Email",
        "Nome utente": "Username",
        "già esistente": "already exists",
        "non trovato": "not found",
        "non valido": "invalid",
        "con successo": "successfully",
        "salvati": "saved",
        "recuperati": "retrieved",
        "trovati": "found",
        # Field descriptions
        "Numero di": "Number of",
        "Giorni indietro": "Days back",
        "da cercare": "to search",
        "da restituire": "to return",
        "Nome del prodotto": "Product name",
        "Versione del prodotto": "Product version",
        "opzionale": "optional",
        # Error messages
        "deve essere": "must be",
        "almeno": "at least",
        "caratteri": "characters",
        "lungo": "long",
        # Response messages
        "ultimo": "last",
        "ultimi": "last",
        "giorni": "days",
        "giorno": "day",
    }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        # Apply translations
        for italian, english in translations.items():
            content = content.replace(italian, english)

        # Only write if changes were made
        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✅ Translated: {file_path}")
            return True
        else:
            print(f"⏭️  No changes: {file_path}")
            return False

    except Exception as e:
        print(f"❌ Error translating {file_path}: {e}")
        return False


def main():
    """Main translation function"""

    # Files to translate
    files_to_translate = [
        "app/routes/cves.py",
        "app/routes/auth.py",
        "app/routes/user.py",
        "app/routes/assets.py",
        "app/services/cve_service.py",
        "app/services/nist_nvd.py",
        "app/utils/auth.py",
        "app/dependencies.py",
    ]

    translated_count = 0

    print("🌐 Starting translation process...")
    print("=" * 50)

    for file_path in files_to_translate:
        if os.path.exists(file_path):
            if translate_file(file_path):
                translated_count += 1
        else:
            print(f"⚠️  File not found: {file_path}")

    print("=" * 50)
    print(f"🎉 Translation complete! Modified {translated_count} files")


if __name__ == "__main__":
    main()
