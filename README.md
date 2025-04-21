*Identify hashing algorithms used in passwords (MD5, SHA-1, bcrypt, NTLM, etc.)*

✨ Features
✅ Detects 25+ hash types (MD5, SHA-1, SHA-256, bcrypt, NTLM, WordPress, Joomla, etc.)
✅ Identifies salt patterns and encoding (Base64, Hex)
✅ Provides Hashcat & John the Ripper compatibility info
✅ JSON output for automation
✅ Fast, lightweight, and easy to use

📥 Installation:
      $ git clone https://github.com/AlmasHacker/hash-identifier.git
      $ cd hash-identifier
      $ python3 -m pip install -r requirements.txt  # (if any dependencies)

🚀 Usage:
      $ python3 hash_identifier.py [HASH] [OPTIONS]

Options:
      Flag	Description
      -f    FILE	Analyze hashes from a file
      -j	  Output in JSON format
      -v	  Verbose mode (detailed analysis)

📋 Examples:
      Identify a single hash:
      $ python3 hash_identifier.py "5f4dcc3b5aa765d61d8327deb882cf99"
      $ python3 hash_identifier.py -f hashes.txt (for file)
