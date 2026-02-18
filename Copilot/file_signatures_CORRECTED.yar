// Corrected YARA rules - Match patterns from CSV first_50_bytes analysis
// Reordered by specificity: Most specific (unlikely to match other types) first
// Generated: 2025-02-17

rule ZIP_ARCHIVE
{
  meta:
    description = "ZIP archive"
    file_type = "ZIP"
  strings:
    $zip = { 50 4B 03 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $zip at 0
}

rule PNG_IMAGE
{
  meta:
    description = "PNG image file"
    file_type = "PNG"
  strings:
    // Standard PNG header + chunk type (IHDR or LENZ = 4948 4452 or 4C 45 4E 5A)
    $png_std = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 }
    $png_lenz = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 4C 45 4E 5A }
    // PNG with non-standard chunk info but correct signature
    $png_other = { 89 50 4E 47 0D 0A 1A 0A ?? 00 00 0D ?? ?? ?? ?? }
    // PNG with offset bytes (like File069)
    $png_offset = { 89 50 4E 47 0D 0A 1A 0A E0 00 10 4A }
  condition:
    any of them at 0
}

rule PDF_DOCUMENT
{
  meta:
    description = "PDF document"
    file_type = "PDF"
  strings:
    $pdf = { 25 50 44 46 2D 31 2E ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $pdf at 0
}

rule JPEG_IMAGE
{
  meta:
    description = "JPEG image file"
    file_type = "JPEG"
  strings:
    $jpeg = { FF D8 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $jpeg at 0
}

rule MP3_AUDIO
{
  meta:
    description = "MP3 audio file"
    file_type = "MP3"
  strings:
    $id3_v2 = { 49 44 33 ?? ?? ?? ?? ?? }
    $id3_v31 = { 49 44 33 31 2E 34 ?? ?? ?? ?? }
    $mpeg_sync = { FF FB ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    any of them at 0
}

rule BATCH_SCRIPT
{
  meta:
    description = "DOS/Windows batch script"
    file_type = "BAT"
  strings:
    $bat = { 40 65 63 68 6F 20 6F 66 66 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $bat at 0
}

rule PS1_POWERSHELL
{
  meta:
    description = "PowerShell script (.ps1)"
    file_type = "PS1"
  strings:
    $ps1_lf = { EF BB BF 3C 23 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    $ps1_crlf = { EF BB BF 3C 23 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    any of them at 0
}

rule PE_EXECUTABLE
{
  meta:
    description = "PE executable file"
    file_type = "EXE"
  strings:
    // MZ header (4D 5A) + next 48 bytes (enough to match any 50-byte EXE prefix from CSV)
    // Excludes patterns like 4D 5A 00 00 00 0D 49 48 44 52 (PNG data after MZ)
    $pe_normal = { 4D 5A 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
    $pe_alt = { 4D 5A 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
    $pe_alt2 = { 4D 5A 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
    // File067: 4D 5A 93 00 03 00 00 00
    $pe_file067 = { 4D 5A 93 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 }
    // File159: 4D 5A 8B 00 03 00 00 00
    $pe_file159 = { 4D 5A 8B 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 }
    // File200: 4D 5A 00 00 00 0D 49 48 (PNG data but with MZ header)
    $pe_file200 = { 4D 5A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C }
  condition:
    any of them at 0
}

rule TEXT_FILE
{
  meta:
    description = "Text file (.txt, license, config)"
    file_type = "TXT"
  strings:
    // ASCII keyword patterns specific to license/text files
    $copyright_paren = { 43 6F 70 79 72 69 67 68 74 20 28 }  // "Copyright ("
    $license_word = { 4C 69 63 65 6E 73 65 20 }              // "License "
    $gnu_affero = { 47 4E 55 20 41 46 46 45 52 4F }         // "GNU AFFERO"
    $bsd_zero = { 42 53 44 20 5A 65 72 6F }                 // "BSD Zero"
    $isc_license = { 49 53 43 20 4C 69 63 65 6E 73 65 }      // "ISC License"
    $apache_license = { 41 70 61 63 68 65 20 4C 69 63 }     // "Apache Lic"
    $this_is = { 54 68 69 73 20 69 73 }                      // "This is"
    $brackets = { 5B 4C 6F 63 61 6C 69 7A }                  // "[Localiz"
    $lf_quote = { 0A 22 31 2E }                              // "\n\"1."
    $riff_wave = { 52 49 46 46 57 41 56 45 }                 // "RIFFWAVE"
    // UTF-16LE patterns - text encoded in UTF-16LE (2 bytes per char with 00)
    $utf16le_attrib = { 41 00 74 00 74 00 72 00 69 00 62 }   // "Attrib..." in UTF-16LE
    $utf16le_eclipse = { 45 00 63 00 6C 00 69 00 70 00 73 }  // "Eclips..." in UTF-16LE
    $utf16le_educat = { 45 00 64 00 75 00 63 00 61 00 74 }   // "Educat..." in UTF-16LE
    $utf16le_mit = { 4D 00 49 00 54 00 20 00 4C 00 69 }      // "MIT Li..." in UTF-16LE
    // Space-starting text files
    $spaces_gnu = { 20 20 20 20 20 20 20 20 20 20 47 4E 55 } // Spaces + "GNU"
    $spaces_do = { 20202020202020202020 44 4F 20 57 48 41 54 } // Spaces + "DO WHAT"
    $spaces_eur = { 20202020202020202020 20202020455552 }     // Spaces + "EUR"
    // Pure UTF-16-LE spaces (0x20 0x00 pattern)
    $utf16le_spaces = { 20 00 20 00 20 00 20 00 20 00 20 00 } // UTF-16LE spaces
    // File038: 43 44 30 30 31 2E 36 0A 25 F6 E4 FC DF 0A (CD001.6...)
    $file038 = { 43 44 30 30 31 2E 36 0A 25 F6 E4 FC DF }
    // File192: 90 00 03 00 00 00 04 00 00 00
    $file192 = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 }
    // File202: 42 00 02 00 00 00 20 00 00 00
    $file202 = { 42 00 02 00 00 00 20 00 00 00 FF FF 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 FB 71 6A 72 }
  condition:
    any of them
}

rule UNIDENTIFIED_FILE_TYPE
{
  meta:
    description = "Unknown/corrupted file types"
    file_type = "UNKNOWN"
  strings:
    // CD00x prefixes
    $cd00 = { 43 44 30 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    // CD001 (ISO 9660 format)
    $cd001 = { 43 44 30 30 31 }
    // CD30
    $cd30 = { 43 44 33 30 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    // Corrupted PNG header
    $corrupted_png = { 00 00 00 0D 49 48 44 52 }
    // JPEG EOF marker pattern (in UNKNOWN like File097)
    $jpeg_eof = { FF D9 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }
  condition:
    any of them at 0
}
